#include "server.h"

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
        char str[3];
        sprintf(str,"%d",query->q_type);
        LOG(LOG_INFO, "Query %s, %s(%s)\n", query->name, str, LookupType(query->q_type));
        switch (query->q_type) {
        case DNS_A_RECORD:
            if (inHosts(query->name)) {
                buffer = BuildDnsResponsePacket(query->name, &packet_length, &query->id, DNS_A_RECORD, GetHostsEntry(query->name, 'A'), DEFAULT_TTL);
                LOG(LOG_DBG, "Hit hosts entry: %s\n", query->name);
                if (sendto(client_fd, buffer, packet_length, 0, client_addr, n_size) < 0) //发回hosts对应的信息
                    LOG(LOG_ERR, "Failed to send response\n");
            }
            else if (enable_mem_cache){
                if (isCached(query->name)) {
                    buffer = BuildDnsResponsePacket(query->name, &packet_length, &query->id, DNS_A_RECORD, GetCacheEntry(query->name, 'A'), DEFAULT_TTL);
                }
            }
            break;
        case DNS_AAAA_RECORD:
            if (inHosts(query->name)){
                buffer = BuildDnsResponsePacket(query->name, &packet_length, &query->id, DNS_AAAA_RECORD, GetHostsEntry(query->name, 'B'), DEFAULT_TTL);
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
            if (!upstream_answer)
                return; //上游无响应直接返回
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
    memcpy(&header, buffer_index, 3 * sizeof(uint16_t));
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

void *BuildDnsResponsePacket(const char *domain_name, 
                             int *packet_size, 
			                 const int request_id, 
                             const int response_q_type, 
                             const void *answer, 
                             const int ttl) {

    struct dns_header *header;
    struct dns_query_trailer *q_trailer;
    size_t domain_length, question_size, total_size, token_length, answer_size;
    char *buffer, *dnspacket, *token_index;
    char temp_buffer[MAX_DOMAIN_LENGTH + 1];

    domain_length = strlen(domain_name);
    if (domain_length > MAX_DOMAIN_LENGTH) {
        LOG(LOG_WARN, "Queried name too long: %s\n", domain_name);
        return NULL;
    }

    if (answer)
        answer_size = response_q_type == DNS_A_RECORD ? 
                sizeof(struct dns_rr_trailer_A) : sizeof(struct dns_rr_trailer_AAAA);
    else
        answer_size = 2 * sizeof(uint16_t) + 5 * sizeof(uint32_t); //SOA记录格式
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
    memset(&header, 0, HEADER_SIZE);
    header->id = htons(request_id);
    if (answer) {
        header->flags = htons(DNS_RECURSION_AVAIL);
        header->an_count = htons(1);
        header->ns_count = htons(0);
    }
    else {
        header->flags = htons(DNS_RECURSION_AVAIL | DNS_NAME_ERROR); //NXDOMAIN
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
    if (answer)
        q_trailer->q_type = htons(response_q_type);
    else
        q_trailer->q_type = htons(DNS_SOA_RECORD); //SOA记录
    q_trailer->q_class = htons(DNS_INET_ADDR);

    buffer += 2 * sizeof(uint16_t);
    
    //资源记录区
    if (!answer)
        memset(buffer, 0, answer_size);
    else if (response_q_type == DNS_A_RECORD) {
        struct dns_rr_trailer_A *rr_trailer = (struct dns_rr_trailer_A *)buffer;
        rr_trailer->rr_class = htons(DNS_INET_ADDR);
        rr_trailer->rr_type = htons(DNS_A_RECORD);
        rr_trailer->rr_domain_pointer = htons(0xc00c);
        rr_trailer->rdata_length = sizeof(uint32_t);
        rr_trailer->rr_ttl = htons(3600);
        rr_trailer->ip_addr = htonl(*(uint32_t *)answer);
    }
    else {
        struct dns_rr_trailer_AAAA *rr_trailer = (struct dns_rr_trailer_AAAA *)buffer;
        rr_trailer->rr_class = htons(DNS_INET_ADDR);
        rr_trailer->rr_type = htons(DNS_A_RECORD);
        rr_trailer->rr_domain_pointer = htons(0xc00c);
        rr_trailer->rdata_length = sizeof(uint32_t);
        rr_trailer->rr_ttl = htons(3600);
        memcpy(&rr_trailer->ip6_addr, answer, sizeof(__uint128_t));
    }

    return dnspacket;
}