#include "server.h"

void ProcessDnsQuery(void *received_packet_buffer, int received_packet_length){
    struct dns_request *query;
    char *buffer;
    int q_count,packet_length;

    query = ParseDnsQuery(received_packet_buffer, received_packet_length, &q_count);

    if (q_count == -1)
        //关闭socket，直接丢包
        return; 
    else if (!query)
        //直接转发
        return;
    else {
        char str[3];
        sprintf(str,"%d",query->q_type);
        LOG(LOG_DBG, "Query %s, %s(%s)", query->name, str, LookupType(query->q_type));
        switch (query->q_type) {
        case DNS_A_RECORD:
            if (inHosts(query->name)) {
                buffer = BuildDnsRequestPacket(query->name, &packet_length, &query->id, DNS_A_RECORD);
                SendBack(buffer);
            }
            if (enable_mem_cache){
                if (isCached(query->name)) {

                }
            }
            break;
        case DNS_AAAA_RECORD:
            if (inHosts(query->name)){
                buffer = BuildDnsRequestPacket(query->name, &packet_length, &query->id, DNS_AAAA_RECORD);
                SendBack(buffer);
            }
            else if (isCached(query->name)) {}
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
    if (!(header.flags & DNS_USE_RECURSION)) 
        LOG(LOG_INFO, "Receiving a non recursive query\n");
        return NULL; //！转发

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

    answer_size = response_q_type == DNS_A_RECORD ? 
                sizeof(struct dns_rr_trailer_A) : sizeof(struct dns_rr_trailer_AAAA);
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
    header->flags = htons(DNS_USE_RECURSION);
    header->qd_count = htons(1);
    header->an_count = htons(0);
    header->ns_count = htons(0);
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

    if (response_q_type == DNS_A_RECORD) {
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