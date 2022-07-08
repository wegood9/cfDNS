#include "server.h"
#include "hosts.h"

static const char SOA_trail[66] = {0x00,0x40,0x01,0x61,0x0c,0x67,0x74,0x6c,0x64,0x2d,
                            0x73,0x65,0x72,0x76,0x65,0x72,0x73,0x03,0x6e,0x65,
                            0x74,0x00,0x05,0x6e,0x73,0x74,0x6c,0x64,0x0c,0x76,
                            0x65,0x72,0x69,0x73,0x69,0x67,0x6e,0x2d,0x67,0x72,
                            0x73,0x03,0x63,0x6f,0x6d,0x00,0x00,0x00,0x07,0x08,
                            0x00,0x00,0x07,0x08,0x00,0x00,0x03,0x84,0x00,0x09,
                            0x3a,0x80,0x00,0x01,0x51,0x80};

void ProcessDnsQuery(const int client_fd, const struct sockaddr *client_addr , void *received_packet_buffer, int received_packet_length){
    struct dns_request *query;
    char *upstream_answer, *buffer;
    int q_count, packet_length;
    int n_size = sizeof(struct sockaddr);

    query = ParseDnsQuery(received_packet_buffer, received_packet_length, &q_count);

    if (q_count == -1)
        //关闭socket，直接丢包
        return;
    //收到未知类型DNS请求，不处理直接转发
    if (!query) {
        upstream_answer = SendDnsRequest(received_packet_buffer, received_packet_length, &packet_length);
        free(received_packet_buffer);
        if (!upstream_answer)
            return; //上游无响应直接返回
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

                if (sendto(client_fd, buffer, packet_length, 0, client_addr, n_size) < 0) //发回hosts对应的信息
                    LOG(LOG_ERR, "Failed to send response\n");
            }

            else if (enable_mem_cache){
                if (isCached(query->name)) {
                    buffer = BuildDnsResponsePacket(query->name, &packet_length, query->id, DNS_A_RECORD, GetCacheEntry(query->name, 'A'), DEFAULT_TTL);
                }
            }
            break;
        case DNS_AAAA_RECORD:
            hosts_entry = inHosts(hosts_trie, query->name);

            if (hosts_entry) {
                buffer = BuildDnsResponsePacket(query->name, &packet_length, query->id, DNS_AAAA_RECORD, GetHostsEntry(hosts_entry, 'B'), DEFAULT_TTL);
                LOG(LOG_DBG, "Hit hosts entry: %s\n", query->name);
                
                if (sendto(client_fd, buffer, packet_length, 0, client_addr, n_size) < 0) //发回hosts对应的信息
                    LOG(LOG_ERR, "Failed to send response\n");
            }

            else if (isCached(query->name)) {

            }
            break;
        default:
            //直接转发
            upstream_answer = SendDnsRequest(received_packet_buffer, received_packet_length, &packet_length);
            free(received_packet_buffer);
            if (!upstream_answer) {
                LOG(LOG_WARN, "Upstream did not respond\n");
                return; //上游无响应直接返回
            }
            else {
                if (sendto(client_fd, upstream_answer, packet_length, 0, client_addr, n_size) < 0)
                    LOG(LOG_ERR, "Failed to send response\n");
                free(upstream_answer);
            }
            break;
        }
    }
}

struct dns_request *ParseDnsQuery(void *packet_buffer, int packet_length, int *q_count) {

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
                             const int ttl) {

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
    if ((response_q_type == DNS_A_RECORD && !*(uint32_t *)answer) || 
            (response_q_type == DNS_AAAA_RECORD && !(*(uint64_t *)answer) && !(*(uint64_t *)(answer+8)) ))
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
        rr_trailer->rr_ttl = htons(DEFAULT_TTL);
        buffer += 10;
        *(uint16_t *)buffer  = htons(sizeof(uint32_t)); //RDATA长度
        buffer += 2;
        *(uint32_t *)buffer = *(uint32_t *)answer;
    }
    else {
        struct dns_rr_trailer_AAAA *rr_trailer = (struct dns_rr_trailer_AAAA *)buffer;
        rr_trailer->rr_class = htons(DNS_INET_ADDR);
        rr_trailer->rr_type = htons(DNS_AAAA_RECORD);
        rr_trailer->rr_domain_pointer = htons(0xc00c);
        rr_trailer->rr_ttl = htons(DEFAULT_TTL);
        buffer += 10;
        *(uint16_t *)buffer  = htons(sizeof(__uint128_t)); //RDATA长度
        buffer += 2;
        memcpy(buffer, answer, sizeof(__uint128_t));
    }

    return dnspacket;
}