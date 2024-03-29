#include <pthread.h>
#include<stdbool.h>
#include<stdlib.h>
#include<stdio.h>
#include<string.h>
#include<netinet/in.h>
#include<stdint.h>

#include "server.h"
#include "hosts.h"
#include "debug.h"
#include "protocol.h"
#include "config.h"
#include "client.h"

static const char SOA_trail[66] = {0x00,0x40,0x01,0x61,0x0c,0x67,0x74,0x6c,0x64,0x2d,
                            0x73,0x65,0x72,0x76,0x65,0x72,0x73,0x03,0x6e,0x65,
                            0x74,0x00,0x05,0x6e,0x73,0x74,0x6c,0x64,0x0c,0x76,
                            0x65,0x72,0x69,0x73,0x69,0x67,0x6e,0x2d,0x67,0x72,
                            0x73,0x03,0x63,0x6f,0x6d,0x00,0x00,0x00,0x07,0x08,
                            0x00,0x00,0x07,0x08,0x00,0x00,0x03,0x84,0x00,0x09,
                            0x3a,0x80,0x00,0x01,0x51,0x80};

static struct dns_request *ParseDnsQuery(void *received_packet_buffer, int received_packet_length, int *q_count);
static void ModifyID(void *buffer, uint16_t id);
static bool MatchIPv4Cf(uint32_t *ip);
static bool MatchIPv6Cf(struct in6_addr *ip6);

void ProcessDnsQuery(const int client_fd, const struct sockaddr_storage *client_addr , void *received_packet_buffer, int received_packet_length){
    struct dns_request *query = NULL;
    struct dns_cache *cache_entry = NULL;
    struct dns_response *server_response = NULL;
    struct dns_response *server_response_entry = NULL;
    char *upstream_answer = NULL, *buffer = NULL;
    int q_count, packet_length, an_count;
    uint16_t cache_req_id;
    int n_size = sizeof(struct sockaddr_storage);
    uint32_t name_hash, cache_ttl;
    int time_watch = time(NULL);

    query = ParseDnsQuery(received_packet_buffer, received_packet_length, &q_count);

    if (q_count == -1); //直接丢包

    //收到未知类型DNS请求，不处理直接转发
    if (!query) {
        upstream_answer = SendDnsRequest(received_packet_buffer, received_packet_length, &packet_length);
        if (!upstream_answer); //上游无响应直接返回
        else {
            if (sendto(client_fd, upstream_answer, packet_length, 0, client_addr, n_size) < 0)
                LOG(LOG_ERR, "Failed to send response\n");
            free(upstream_answer);
        }
    }
    else {
        char str[10];
        struct trieNode *hosts_entry;
        sprintf(str,"%d",query->q_type);
        LOG(LOG_INFO, "Query %s, %s(%s)\n", query->name, str, LookupType(query->q_type));
        switch (query->q_type) {
        case DNS_A_RECORD:
            hosts_entry = inHosts(hosts_trie, query->name);
            
            if (hosts_entry) {
                buffer = BuildDnsResponsePacket(query->name, &packet_length, query->id, DNS_A_RECORD, GetHostsEntry(hosts_entry, 'A'), DEFAULT_TTL);
                LOG(LOG_DBG, "Hit hosts entry: %s\n", query->name);

                if (sendto(client_fd, buffer, packet_length, 0, client_addr, n_size) < 0) //发回 hosts 对应的信息
                    LOG(LOG_ERR, "Failed to send response\n");
                free(buffer);
            }
            
            else if (raw_config.enable_mem_cache) {
                name_hash = hashlittle(query->name, strlen(query->name), HASH_A_INITVAL);

                pthread_cleanup_push(pthread_mutex_unlock, (void *) &cache_lock)
                    pthread_mutex_lock(&cache_lock);
                    cache_entry = GetCacheEntry(name_hash);
                    pthread_mutex_unlock(&cache_lock);
                pthread_cleanup_pop(0);

                if (cache_entry) {
                    buffer = BuildDnsResponsePacket(query->name, &packet_length, query->id, DNS_A_RECORD, &cache_entry->ip4, cache_entry->ttl);
                    LOG(LOG_DBG, "Hit cache entry: %s\n", query->name);

                    if (sendto(client_fd, buffer, packet_length, 0, client_addr, n_size) < 0) //发回 cache 对应的信息
                        LOG(LOG_ERR, "Failed to send response\n");
                    free(buffer);

                    if (cache_entry->expire_time + 60 <= time(NULL)) {
                        //预超时机制
                        LOG(LOG_DBG, "Pre-timeout: %s\n", query->name);
                        buffer = BuildDnsRequestPacket(query->name, &packet_length, &cache_req_id, DNS_A_RECORD);
                        upstream_answer = SendDnsRequest(buffer, packet_length, &packet_length);
                        free(buffer);
                        server_response = ParseDnsResponse(upstream_answer, packet_length, cache_req_id, query->name, &an_count);
                        server_response_entry = GetRecordPointerFromResponse(server_response, an_count, DNS_A_RECORD);
                        if (server_response_entry) {
                            int cache_ttl = server_response_entry->cache_time < raw_config.min_cache_ttl ?
                                               raw_config.min_cache_ttl : server_response_entry->cache_time;
                            cache_entry->expire_time = cache_ttl + time(NULL);
                            cache_entry->ttl = cache_ttl;
                            cache_entry->ip4 = server_response_entry->ip_addr;
                        }
                    }
                }

                else {
                    //Cache 中无此记录

                    //优先 DoH
                    if (loaded_config.doh_num)
                        upstream_answer = QueryDoH(query->name, &packet_length, cache_req_id, DNS_A_RECORD);
                    //fallback 到普通服务器
                    if (!upstream_answer){
                        buffer = BuildDnsRequestPacket(query->name, &packet_length, &cache_req_id, DNS_A_RECORD);
                        upstream_answer = SendDnsRequest(buffer, packet_length, &packet_length);
                        free(buffer);
                    }

                    server_response = ParseDnsResponse(upstream_answer, packet_length, cache_req_id, query->name, &an_count);
                    

                    if (an_count >= 0) {
                        //可能的无效回应，不缓存
                        server_response_entry = GetRecordPointerFromResponse(server_response, an_count, DNS_A_RECORD);

                        //cfDNS功能
                        if (raw_config.enable_cfDNS && server_response_entry && MatchIPv4Cf(&(server_response_entry->ip_addr))) {
                            //根据设置构造DNS回复
                            if (loaded_config.cf_IP_version == 4) {
                                buffer = BuildDnsResponsePacket(query->name, &packet_length, query->id, DNS_A_RECORD, &loaded_config.cf_IPv4, 0);
                                InsertHosts(hosts_trie, query->name, &loaded_config.cf_IPv4, NULL);
                            }
                            else {
                                buffer = BuildDnsResponsePacket(query->name, &packet_length, query->id, DNS_A_RECORD, NULL, 0);
                                InsertHosts(hosts_trie, query->name, NULL, &loaded_config.cf_IPv6);
                            }
                            if (sendto(client_fd, buffer, packet_length, 0, client_addr, n_size) < 0) //返回指定ip
                                LOG(LOG_ERR, "Failed to send response\n");
                            
                            
                            free(upstream_answer);
                            free(server_response);
                            free(buffer);
                            break;
                        }

                        ModifyID(upstream_answer, query->id);
                        if (sendto(client_fd, upstream_answer, packet_length, 0, client_addr, n_size) < 0)
                            LOG(LOG_ERR, "Failed to send response\n");
                        
                        if (server_response_entry) {
                            cache_ttl = server_response_entry->cache_time < raw_config.min_cache_ttl ?
                                               raw_config.min_cache_ttl : server_response_entry->cache_time;

                            pthread_cleanup_push(pthread_mutex_unlock, (void *) &cache_lock);
                            pthread_mutex_lock(&cache_lock);
                                AddEntryToCache(name_hash, cache_ttl, &server_response_entry->ip_addr, NULL);
                            pthread_mutex_unlock(&cache_lock);
                            pthread_cleanup_pop(0);
                        }
                    }
                    
                }
                free(upstream_answer);
                free(server_response);

            }

            else {
                //不启用 Cache，直接向上游查询

                //优先使用DoH
                if (loaded_config.doh_num)
                    upstream_answer = QueryDoH(query->name, &packet_length, query->id, DNS_A_RECORD);
                //fallback 到普通服务器
                if (!upstream_answer)
                    upstream_answer = SendDnsRequest(received_packet_buffer, received_packet_length, &packet_length);
                
                //cfDNS功能
                if (raw_config.enable_cfDNS) {
                    server_response = ParseDnsResponse(upstream_answer, packet_length, cache_req_id, query->name, &an_count);
                    server_response_entry = GetRecordPointerFromResponse(server_response, an_count, DNS_A_RECORD);
                    if (server_response_entry && MatchIPv4Cf(&(server_response_entry->ip_addr))) {
                        //根据设置构造DNS回复
                        if (loaded_config.cf_IP_version == 4) {
                            buffer = BuildDnsResponsePacket(query->name, &packet_length, query->id, DNS_A_RECORD, &loaded_config.cf_IPv4, 0);
                            InsertHosts(hosts_trie, query->name, &loaded_config.cf_IPv4, NULL);
                        }
                        else {
                            buffer = BuildDnsResponsePacket(query->name, &packet_length, query->id, DNS_A_RECORD, NULL, 0);
                            InsertHosts(hosts_trie, query->name, NULL, &loaded_config.cf_IPv6);
                        }
                        if (sendto(client_fd, buffer, packet_length, 0, client_addr, n_size) < 0) //返回指定ip
                            LOG(LOG_ERR, "Failed to send response\n");
                        free(upstream_answer);
                        free(server_response);
                        free(buffer);
                        break;
                    }
                    free(server_response);
                }

                if (!upstream_answer)
                    LOG(LOG_WARN, "Upstream did not respond\n"); //上游无响应直接返回
                else {
                    if (sendto(client_fd, upstream_answer, packet_length, 0, client_addr, n_size) < 0)
                        LOG(LOG_ERR, "Failed to send response\n");
                    free(upstream_answer);
                }
            }
            
            break;
        case DNS_AAAA_RECORD:

            if (!raw_config.enable_AAAA) {
                buffer = BuildDnsResponsePacket(query->name, &packet_length, query->id, DNS_AAAA_RECORD, NULL, 0);

                if (sendto(client_fd, buffer, packet_length, 0, client_addr, n_size) < 0) //返回 SOA 记录
                    LOG(LOG_ERR, "Failed to send response\n");
                free(buffer);
                break;
            }


            hosts_entry = inHosts(hosts_trie, query->name);

            if (hosts_entry) {
                buffer = BuildDnsResponsePacket(query->name, &packet_length, query->id, DNS_AAAA_RECORD, GetHostsEntry(hosts_entry, 'B'), DEFAULT_TTL);
                LOG(LOG_DBG, "Hit hosts entry: %s\n", query->name);
                
                if (sendto(client_fd, buffer, packet_length, 0, client_addr, n_size) < 0) //发回hosts对应的信息
                    LOG(LOG_ERR, "Failed to send response\n");
                free(buffer);
            }

            else if (raw_config.enable_mem_cache) {
                name_hash = hashlittle(query->name, strlen(query->name), HASH_AAAA_INITVAL);
                //缓存操作上锁
                pthread_cleanup_push(pthread_mutex_unlock, (void *) &cache_lock)
                    pthread_mutex_lock(&cache_lock);
                    cache_entry = GetCacheEntry(name_hash);
                    pthread_mutex_unlock(&cache_lock);
                pthread_cleanup_pop(0);

                if (cache_entry) {
                    buffer = BuildDnsResponsePacket(query->name, &packet_length, query->id, DNS_AAAA_RECORD, &cache_entry->ip6, cache_entry->ttl);
                    LOG(LOG_DBG, "Hit cache entry: %s\n", query->name);

                    if (sendto(client_fd, buffer, packet_length, 0, client_addr, n_size) < 0) //发回 cache 对应的信息
                        LOG(LOG_ERR, "Failed to send response\n");
                    free(buffer);

                    if (cache_entry->expire_time + 60 <= time(NULL)) {
                        //预超时机制
                        LOG(LOG_DBG, "Pre-timeout: %s\n", query->name);
                        buffer = BuildDnsRequestPacket(query->name, &packet_length, &cache_req_id, DNS_AAAA_RECORD);
                        upstream_answer = SendDnsRequest(buffer, packet_length, &packet_length);
                        free(buffer);
                        server_response = ParseDnsResponse(upstream_answer, packet_length, cache_req_id, query->name, &an_count);
                        server_response_entry = GetRecordPointerFromResponse(server_response, an_count, DNS_AAAA_RECORD);
                        if (server_response_entry) {
                            int cache_ttl = server_response_entry->cache_time < raw_config.min_cache_ttl ?
                                               raw_config.min_cache_ttl : server_response_entry->cache_time;
                            cache_entry->expire_time = cache_ttl + time(NULL);
                            cache_entry->ttl = cache_ttl;
                            cache_entry->ip6 = server_response_entry->ip6_addr;
                        }
                    }
                }

                else {
                    //Cache 中无此记录
                    //优先 DoH
                    if (loaded_config.doh_num)
                        upstream_answer = QueryDoH(query->name, &packet_length, cache_req_id, DNS_AAAA_RECORD);
                    //fallback 到普通服务器
                    if (!upstream_answer){
                        buffer = BuildDnsRequestPacket(query->name, &packet_length, &cache_req_id, DNS_AAAA_RECORD);
                        upstream_answer = SendDnsRequest(buffer, packet_length, &packet_length);
                        free(buffer);
                    }

                    server_response = ParseDnsResponse(upstream_answer, packet_length, cache_req_id, query->name, &an_count);
                    
                    if (an_count >= 0) {
                        server_response_entry = GetRecordPointerFromResponse(server_response, an_count, DNS_AAAA_RECORD);

                        if (raw_config.enable_cfDNS && server_response_entry && MatchIPv6Cf(&(server_response_entry->ip6_addr))) {
                            //根据设置构造DNS回复
                            if (loaded_config.cf_IP_version == 6) {
                                buffer = BuildDnsResponsePacket(query->name, &packet_length, query->id, DNS_AAAA_RECORD, &loaded_config.cf_IPv6, 0);
                                InsertHosts(hosts_trie, query->name, NULL, &loaded_config.cf_IPv6);
                            }
                            else {
                                buffer = BuildDnsResponsePacket(query->name, &packet_length, query->id, DNS_AAAA_RECORD, NULL, 0);
                                InsertHosts(hosts_trie, query->name, &loaded_config.cf_IPv4, NULL);
                            }
                            if (sendto(client_fd, buffer, packet_length, 0, client_addr, n_size) < 0) //返回指定ip
                                LOG(LOG_ERR, "Failed to send response\n");
                            
                            
                            free(upstream_answer);
                            free(server_response);
                            free(buffer);
                            break;
                        }

                        //直接转发响应
                        ModifyID(upstream_answer, query->id);
                        if (sendto(client_fd, upstream_answer, packet_length, 0, client_addr, n_size) < 0)
                            LOG(LOG_ERR, "Failed to send response\n");

                        if (server_response_entry) {
                            cache_ttl = server_response_entry->cache_time < raw_config.min_cache_ttl ?
                                               raw_config.min_cache_ttl : server_response_entry->cache_time;

                            pthread_cleanup_push(pthread_mutex_unlock, (void *) &cache_lock);
                            pthread_mutex_lock(&cache_lock);
                                AddEntryToCache(name_hash, cache_ttl, NULL, &server_response_entry->ip6_addr);
                            pthread_mutex_unlock(&cache_lock);
                            pthread_cleanup_pop(0);
                        }
                    }
                    
                }
                free(upstream_answer);
                free(server_response);
            }

            
            else {
                //不启用Cache时

                //优先使用DoH
                if (loaded_config.doh_num)
                    upstream_answer = QueryDoH(query->name, &packet_length, query->id, DNS_AAAA_RECORD);
                //fallback 到普通服务器
                if (!upstream_answer)
                    upstream_answer = SendDnsRequest(received_packet_buffer, received_packet_length, &packet_length);

                //cfDNS功能
                if (raw_config.enable_cfDNS) {
                    server_response = ParseDnsResponse(upstream_answer, packet_length, cache_req_id, query->name, &an_count);
                    server_response_entry = GetRecordPointerFromResponse(server_response, an_count, DNS_A_RECORD);
                    if (server_response_entry && MatchIPv6Cf(&(server_response_entry->ip6_addr))) {
                        //根据设置构造DNS回复
                        if (loaded_config.cf_IP_version == 6) {
                            buffer = BuildDnsResponsePacket(query->name, &packet_length, query->id, DNS_AAAA_RECORD, &loaded_config.cf_IPv6, 0);
                            InsertHosts(hosts_trie, query->name, NULL, &loaded_config.cf_IPv6);
                        }
                        else {
                            buffer = BuildDnsResponsePacket(query->name, &packet_length, query->id, DNS_AAAA_RECORD, NULL, 0);
                            InsertHosts(hosts_trie, query->name, &loaded_config.cf_IPv4, NULL);
                        }
                        if (sendto(client_fd, buffer, packet_length, 0, client_addr, n_size) < 0) //返回指定ip
                            LOG(LOG_ERR, "Failed to send response\n");
                        free(upstream_answer);
                        free(server_response);
                        free(buffer);
                        break;
                    }
                    free(server_response);
                }

                if (!upstream_answer)
                    LOG(LOG_WARN, "Upstream did not respond\n"); //上游无响应直接返回
                else {
                    if (sendto(client_fd, upstream_answer, packet_length, 0, client_addr, n_size) < 0)
                        LOG(LOG_ERR, "Failed to send response\n");
                    free(upstream_answer);
                }
            }
            break;
        default:
            //直接转发
            upstream_answer = SendDnsRequest(received_packet_buffer, received_packet_length, &packet_length);
            if (!upstream_answer)
                LOG(LOG_WARN, "Upstream did not respond\n"); //上游无响应直接返回
            else {
                if (sendto(client_fd, upstream_answer, packet_length, 0, client_addr, n_size) < 0)
                    LOG(LOG_ERR, "Failed to send response\n");
                free(upstream_answer);
            }
            break;
        }
    }
    
    free(query);
}

static struct dns_request *ParseDnsQuery(void *packet_buffer, int packet_length, int *q_count) {

    int bytes_read;
    char *buffer_index, *packet_end;
    struct dns_header header;
    struct dns_request *requests;
    struct dns_query_trailer q_trailer;

    *q_count = 0;

    if (packet_length < HEADER_SIZE) {
        LOG(LOG_INFO, "Rceiving an invalid DNS query\n");
        *q_count = -1;
        return NULL; //丢弃
    }

    buffer_index = (char *)packet_buffer;
    packet_end = buffer_index + packet_length;

    //处理包头
    memcpy(&header, buffer_index, HEADER_SIZE);
    buffer_index += HEADER_SIZE;

    header.id = ntohs(header.id);
    header.flags = ntohs(header.flags);
    header.qd_count = ntohs(header.qd_count);

    if (header.flags & DNS_IS_RESPONSE) {
        LOG(LOG_INFO, "Rceiving an invalid DNS query\n");
        *q_count = -1;
        return NULL; //丢弃
    }

    if (header.flags & DNS_TRUNCATED) {
        LOG(LOG_WARN, "Query was truncated\n");
        return NULL; //！转发
    }

    //非递归查询，直接转发
    if (!(header.flags & DNS_USE_RECURSION)) {
        LOG(LOG_INFO, "Receiving a non recursive query\n");
        return NULL; //！转发
    }

    //无有效查询，或查询数非1
    if (header.qd_count != 1) { 
        *q_count = -1;
        return NULL; //丢弃
    }

    requests = malloc(sizeof(struct dns_request));
    if (requests == NULL) {
        LOG(LOG_WARN, "Failed to allocate memory for request\n");
        return NULL;
    }
    requests->id = header.id;

    //读取 Query 域名
    bytes_read = ParseDomainName(buffer_index, packet_buffer, packet_length, requests->name);
    if (bytes_read == -1 || !inc(&buffer_index, packet_end, bytes_read)) {
        LOG(LOG_INFO, "Rceiving an invalid DNS query\n");
        *q_count = -1;
        free(requests);
        return NULL; //丢弃
    }

    if (packet_end - buffer_index < 2 * sizeof(uint16_t)) {
        LOG(LOG_INFO, "Rceiving an invalid DNS query\n");
        *q_count = -1;
        free(requests);
        return NULL; //丢弃
    }

    memcpy(&q_trailer, buffer_index, 2 * sizeof(uint16_t));
    q_trailer.q_type = ntohs(q_trailer.q_type);
    q_trailer.q_class = ntohs(q_trailer.q_class);

    if (q_trailer.q_class != DNS_INET_ADDR) {
        LOG(LOG_INFO, "Rceiving an invalid DNS query\n");
        *q_count = -1;
        free(requests);
        return NULL; //丢弃
    }

    requests->q_type = q_trailer.q_type;

    return requests;
}


//构建DNS响应，传入回答为网络序
void *BuildDnsResponsePacket(const char *domain_name, 
                             int *packet_size, 
			                 const uint16_t request_id, 
                             const int response_q_type, 
                             const void *answer_in, 
                             const uint32_t ttl) {

    struct dns_header *header;
    struct dns_query_trailer *q_trailer;
    size_t domain_length, question_size, total_size, token_length, answer_size;
    char *buffer, *dnspacket, *token_index;
    char temp_buffer[MAX_DOMAIN_LENGTH + 1];
    void *answer = answer_in;

    domain_length = strlen(domain_name);
    if (domain_length > MAX_DOMAIN_LENGTH) {
        LOG(LOG_WARN, "Queried name too long: %s\n", domain_name);
        return NULL;
    }

    //返回答案为空或者空指针
    if (!answer_in || (response_q_type == DNS_A_RECORD && !*(uint32_t *)answer_in) || 
            (response_q_type == DNS_AAAA_RECORD && !(*(uint64_t *)answer_in) && !(*(uint64_t *)((char*)answer_in+8)) ))
        answer = NULL;

    if (answer)
        answer_size = response_q_type == DNS_A_RECORD ? 16 : 28; //手工计算答案区长度
    else
        answer_size = 76; //SOA记录格式
    question_size = domain_length + sizeof(struct dns_query_trailer) + 2; //最前的1字节和最后的root
    total_size = answer_size + question_size + HEADER_SIZE;
    *packet_size = total_size;

    dnspacket = buffer = (char *)malloc(total_size);
    if (dnspacket == NULL) {
        LOG(LOG_ERR, "Failed to allocate memory when sending responses\n");
        return NULL;
    }

    //设置包头部分
    header = (struct dns_header *)buffer;

    header->id = htons(request_id);
    if (answer) {
        header->flags = htons(DNS_IS_RESPONSE | DNS_RECURSION_AVAIL);
        header->an_count = htons(1);
        header->ns_count = htons(0);
    }
    else {
        header->flags = htons(DNS_IS_RESPONSE | DNS_RECURSION_AVAIL | DNS_NAME_ERROR); //NXDOMAIN
        header->an_count = htons(0);
        header->ns_count = htons(1);
    }
    header->qd_count = htons(1);
    header->ar_count = htons(0);

    buffer += HEADER_SIZE;

    //分域名
    strcpy(temp_buffer, domain_name);

    token_index = strtok(temp_buffer, ".");
    while (token_index != 0) {
        token_length = strlen(token_index); //子域名长度

        if (token_length > MAX_SUBDOMAIN_LENGTH) {
            LOG(LOG_WARN, "Queried name too long: %s\n", domain_name);
            free(dnspacket);
            return NULL;
        }

        //按字节复制，对应网络序
        *buffer++ = token_length;
        while ((*buffer++ = *token_index++) != 0);

        buffer--; //加入.
        token_index = strtok(NULL, ".");
    }

    *buffer++ = 0; //最后一个字符是.
    q_trailer = (struct dns_query_trailer *)buffer;
    q_trailer->q_type = htons(response_q_type);
    q_trailer->q_class = htons(DNS_INET_ADDR);

    buffer += 2 * sizeof(uint16_t);
    
    //资源记录区
    if (!answer) {
        //返回固定 SOA 记录
        struct dns_rr_trailer_A *rr_trailer = (struct dns_rr_trailer_A *)buffer;
        rr_trailer->rr_class = htons(DNS_INET_ADDR);
        rr_trailer->rr_type = htons(DNS_SOA_RECORD);
        rr_trailer->rr_domain_pointer = htons(0xc00c);
        rr_trailer->rr_ttl = 0;
        buffer += 10;
        memcpy(buffer, SOA_trail, 66);
    }
    else if (response_q_type == DNS_A_RECORD) {
        struct dns_rr_trailer_A *rr_trailer = (struct dns_rr_trailer_A *)buffer;
        rr_trailer->rr_class = htons(DNS_INET_ADDR);
        rr_trailer->rr_type = htons(DNS_A_RECORD);
        rr_trailer->rr_domain_pointer = htons(0xc00c);
        buffer += 10;
        *(uint16_t *)buffer  = htons(sizeof(uint32_t)); //RDATA长度
        *(uint32_t *)((char*)buffer - 4) = htonl(ttl);
        buffer += 2;
        *(uint32_t *)buffer = *(uint32_t *)answer;
    }
    else {
        struct dns_rr_trailer_AAAA *rr_trailer = (struct dns_rr_trailer_AAAA *)buffer;
        rr_trailer->rr_class = htons(DNS_INET_ADDR);
        rr_trailer->rr_type = htons(DNS_AAAA_RECORD);
        rr_trailer->rr_domain_pointer = htons(0xc00c);
        buffer += 10;
        *(uint16_t *)buffer  = htons(sizeof(__uint128_t)); //RDATA长度
        *(uint32_t *)((char*)buffer - 4) = htonl(ttl);
        buffer += 2;
        memcpy(buffer, answer, sizeof(__uint128_t));
    }

    return dnspacket;
}

void ModifyID(void *buffer, uint16_t id) {
    if (buffer)
        *(uint16_t *)buffer = htons(id);
}

bool MatchIPv4Cf(uint32_t *ip) {
    for (int i = 0; i < loaded_config.cf4_num; i++)
        if (cidr_match(ip, &(loaded_config.cf_IPv4_range[i]->ip4), loaded_config.cf_IPv4_range[i]->bits))
            return true;
    return false;
}

bool MatchIPv6Cf(struct in6_addr *ip6) {
    for (int i = 0; i < loaded_config.cf6_num; i++)
        if (cidr_match(ip6, &(loaded_config.cf_IPv6_range[i]->ip6), loaded_config.cf_IPv6_range[i]->bits))
            return true;
    return false;
}