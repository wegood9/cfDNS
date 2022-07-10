#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <netinet/in.h>
#include <stdint.h>
#include <errno.h>
#include <poll.h>
#include <limits.h>


#include "debug.h"
#include "protocol.h"
#include "config.h"

#define MAX_AN_COUNT 50

void *BuildDnsRequestPacket(const char *domain_name, int *packet_size, 
			       uint16_t *request_id, int request_q_type) {

    struct dns_header *header;
    struct dns_query_trailer *q_trailer;
    size_t domain_length, question_size, total_size, token_length;
    char *buffer, *dnspacket, *token_index;
    char temp_buffer[MAX_DOMAIN_LENGTH + 1];

    domain_length = strlen(domain_name);
    if (domain_length > MAX_DOMAIN_LENGTH) {
        LOG(LOG_WARN, "Queried name too long: %s\n", domain_name);
        return NULL;
    }

    question_size = domain_length + sizeof(struct dns_query_trailer) + 2; //最前的1字节和最后的root
    total_size = question_size + HEADER_SIZE;
    *packet_size = total_size;

    dnspacket = buffer = (char *)malloc(total_size);
    if (dnspacket == NULL) {
        LOG(LOG_ERR, "Failed to allocate memory when sending requests\n");
        return NULL;
    }

    //设置包头部分
    *request_id = rand() % UINT16_MAX;
    header = (struct dns_header *)buffer;
    memset(header, 0, HEADER_SIZE);
    header->id = htons(*request_id);
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
    q_trailer->q_type = htons(request_q_type);
    q_trailer->q_class = htons(DNS_INET_ADDR);

    return dnspacket;
}

struct dns_response *ParseDnsResponse(void *packet_buffer, 
					int packet_length, 
					int expected_id, 
					const char *domain_name, 
					int *answer_count) {

    int i, bytes_read, authoritative;
    char buffer[MAX_DOMAIN_LENGTH + 1];
    char *buffer_index, *packet_end;
    uint8_t reply_code;
    uint16_t rdata_length;
    struct dns_header header;
    struct dns_response *responses;

    *answer_count = 0;
    if (!packet_buffer)
        return NULL;
    if (packet_length < HEADER_SIZE) {
        LOG(LOG_INFO, "Rceiving an invalid DNS response\n");
        *answer_count = -1;
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
    header.an_count = ntohs(header.an_count);
    header.ns_count = ntohs(header.ns_count);
    header.ar_count = ntohs(header.ar_count);

    //检查ID
    if (header.id != expected_id) {
        LOG(LOG_INFO, "Response id does not match request id\n");
        *answer_count = -1;
        return NULL; //丢弃
    }

    if (!(header.flags & DNS_IS_RESPONSE)) {
        LOG(LOG_INFO, "Header does not contain response flag\n");
        *answer_count = -1;
        return NULL; //丢弃
    }

    if (header.flags & DNS_TRUNCATED) {
        LOG(LOG_WARN, "Response was truncated\n");
        return NULL; //！转发
    }

    //非递归服务器，可能有传输错误
    if (!(header.flags & DNS_RECURSION_AVAIL)) 
        return NULL; //！转发

    reply_code = header.flags & DNS_REPLY_CODE_MASK;
    if (reply_code){
        switch (reply_code) {
        case DNS_FORMAT_ERROR:
            LOG(LOG_INFO, "Upstream server unable to interpret query\n");
            break;
        case DNS_SERVER_FAILURE:
            LOG(LOG_INFO, "Unable to process due to upstream server error\n");
            break;
        case DNS_NOT_IMPLEMENTED:
            LOG(LOG_INFO, "Upstream server does not support requested query type\n");
            break;
        case DNS_REFUSED:
            LOG(LOG_INFO, "Upstream server refused query\n");
            break;
        case DNS_NAME_ERROR:
            *answer_count = 0; //NXDOMAIN
        default:
            break;
        }
        return NULL; //！转发
    }

    //无有效回答直接转发
    if (header.an_count < 1) { 
        *answer_count = 0;
        return NULL; //！转发
    }

    if (header.an_count > MAX_AN_COUNT){
        LOG(LOG_INFO, "Response contains too many answers\n");
        header.an_count = MAX_AN_COUNT; //响应中答案数量过多
    }

    //是否为权威响应
    authoritative = header.flags & DNS_AUTH_ANS;

    //读取 Query 域名
    bytes_read = ParseDomainName(buffer_index, packet_buffer, packet_length, buffer);
    if (bytes_read == -1 || !inc(&buffer_index, packet_end, bytes_read)) {
        LOG(LOG_INFO, "Receiving an invalid response\n");
        *answer_count = -1;
        return NULL; //丢弃
    }

    if (strcmp(buffer, domain_name) != 0) {
        LOG(LOG_INFO, "The response domain does not match the query\n");
        *answer_count = -1;
        return NULL; //丢弃
    }
  
    //跳过 QTYPE 和 QCLASS 
    if (!inc(&buffer_index, packet_end, 2 * sizeof(uint16_t))) {
        LOG(LOG_INFO, "Receiving an invalid response\n");
        *answer_count = -1;
        return NULL; //丢弃
    }
  
    //回答部分
    *answer_count = header.an_count;
    responses = malloc(sizeof(struct dns_response) * header.an_count);
    if (responses == 0) {
        LOG(LOG_WARN, "Failed to allocate memory for processing response");
        return NULL; //！转发
    }
    memset(responses, 0, sizeof(struct dns_response) * header.an_count);

    for (i = 0; i < header.an_count; ++i) {
        responses[i].authoritative = authoritative;

        //读取响应域名
        bytes_read = ParseDomainName(buffer_index, packet_buffer, packet_length, buffer);
        if (bytes_read == -1) {
            free(responses);
            LOG(LOG_INFO, "Receiving an invalid response\n");
            *answer_count = -1;
            return NULL; //丢弃
        }

        if (!inc(&buffer_index, packet_end, bytes_read)) {
            free(responses);
            LOG(LOG_INFO, "Receiving an invalid response\n");
            *answer_count = -1;
            return NULL; //丢弃
        }

        responses[i].response_type = ntohs(*(uint16_t *)buffer_index);

        if (!inc(&buffer_index, packet_end, sizeof(uint16_t))) {
            free(responses);
            LOG(LOG_INFO, "Receiving an invalid response\n");
            *answer_count = -1;
            return NULL; //丢弃
        }

        if (ntohs(*(uint16_t *)buffer_index) != DNS_INET_ADDR) {
            free(responses);
            LOG(LOG_INFO, "Receiving an invalid response\n");
            *answer_count = -1;
            return NULL; //丢弃
        }

        if (!inc(&buffer_index, packet_end, sizeof(uint16_t))) {
            free(responses);
            LOG(LOG_INFO, "Receiving an invalid response\n");
            *answer_count = -1;
            return NULL; //丢弃
        }

        responses[i].cache_time = ntohl(*(uint32_t *)buffer_index);
        
        if (raw_config.ttl_multiplier) {
            responses[i].cache_time *= raw_config.ttl_multiplier;

            if (responses[i].cache_time < ntohl(*(uint32_t *)buffer_index))
                responses[i].cache_time = UINT32_MAX; //判断溢出
        }
        
        if (!inc(&buffer_index, packet_end, sizeof(uint32_t))) {
            free(responses);
            LOG(LOG_INFO, "Receiving an invalid response\n");
            *answer_count = -1;
            return NULL; //丢弃
        }

        //每个响应中RDATA长度
        rdata_length = ntohs(*(uint16_t *)buffer_index);
        if (!inc(&buffer_index, packet_end, sizeof(uint16_t))) {
            free(responses);
            LOG(LOG_INFO, "Receiving an invalid response\n");
            *answer_count = -1;
            return NULL; //丢弃
        }

        switch (responses[i].response_type) {
        case DNS_A_RECORD:
            responses[i].ip_addr = ntohl(*(uint32_t *)buffer_index);
            break;

        case DNS_AAAA_RECORD:
            memcpy(&responses[i].ip6_addr, buffer_index, sizeof(__uint128_t));
            break;
        //！以下仅供展示，实际不做处理
        case DNS_NS_RECORD:
            bytes_read = ParseDomainName(buffer_index, packet_buffer, packet_length, responses[i].name);
            if (bytes_read == -1) {
	            free(responses);
	            LOG(LOG_INFO, "Receiving an invalid response\n");
                *answer_count = -1;
	            return NULL; //丢弃
            }
        break;

        case DNS_CNAME_RECORD:
            bytes_read = ParseDomainName(buffer_index, packet_buffer, packet_length, responses[i].name);
            if (bytes_read == -1) {
	            free(responses);
	            LOG(LOG_INFO, "Receiving an invalid response\n");
                *answer_count = -1;
	            return NULL; //丢弃
            }
        break;

        case DNS_MX_RECORD:
            responses[i].preference = ntohs(*(uint16_t *)buffer_index);

            if (!inc(&buffer_index, packet_end, sizeof(uint16_t))) {
	            free(responses);
	            LOG(LOG_INFO, "Receiving an invalid response\n");
                *answer_count = -1;
	            return NULL; //丢弃
            }

            bytes_read = ParseDomainName(buffer_index, packet_buffer, packet_length, responses[i].name);      
            if (bytes_read == -1) {
	            free(responses);
	            LOG(LOG_INFO, "Receiving an invalid response\n");
                *answer_count = -1;
	            return NULL; //丢弃
            }
            rdata_length -= sizeof(uint16_t);
            break;
        default:
            break;
        }

        //处理下一个数据段，最后一个段可以越界
        if (!inc(&buffer_index, packet_end, rdata_length) && (i + 1 < header.an_count)) {
            free(responses);
	        LOG(LOG_INFO, "Receiving an invalid response\n");
            *answer_count = -1;
	        return NULL; //丢弃
        }
    }

    return responses;
}

char *SendDnsRequest(char *query, int length, int *recv_length) {
    char server_num = loaded_config.udp_num + loaded_config.tcp_num;
    char chosen_server = rand() % server_num;
    int sockfd = 0;
    char *buffer;
    int n_size = sizeof(struct sockaddr);

    struct pollfd fd;
    int res;

    fd.events = POLLIN;

    if (chosen_server < loaded_config.udp_num) {
        if ((sockfd = socket(loaded_config.udp_server[chosen_server]->ss_family, SOCK_DGRAM, 0)) < 0 &&
                connect_with_timeout(sockfd, 
                                     (struct sockaddr*)loaded_config.udp_server[chosen_server], 
                                     sizeof(struct sockaddr), 
                                     GLOBAL_TIMEOUT)
                                     < 0) {
            LOG(LOG_ERR, "Failed to create socket for recursive query: %s\n", strerror(errno));
            close(sockfd);
            return NULL;
        }

        if(sendto(sockfd, query, length, 0, loaded_config.udp_server[chosen_server], n_size) < 0) {
            LOG(LOG_ERR, "Failed to query upstream: %s\n", strerror(errno));
            close(sockfd);
            return NULL;
        }

        buffer = malloc(513 * sizeof(uint8_t));
        *recv_length = 0;

        //使用poll的超时机制
        fd.fd = sockfd;
        res = poll(&fd, 1, GLOBAL_TIMEOUT);
        if (res > 0)
            *recv_length = recvfrom(sockfd, buffer, 512, 0, (struct sockaddr*)loaded_config.udp_server[chosen_server], &n_size);
        if (*recv_length < 20) {
            LOG(LOG_WARN, "Failed to receive answer from %s\n", raw_config.UDP_server[chosen_server]);
            close(sockfd);
            free(buffer);
            return NULL;
        }
        else {
            buffer[*recv_length] = 0;
            close(sockfd);
            return buffer;
        }
    }
    else if (chosen_server < loaded_config.udp_num + loaded_config.tcp_num) {
        chosen_server -= loaded_config.udp_num;
        if ((sockfd = socket(loaded_config.tcp_server[chosen_server]->ss_family, SOCK_STREAM, 0)) < 0) {
            LOG(LOG_ERR, "Failed to create socket for recursive query: %s\n", strerror(errno));
            close(sockfd);
            return NULL;
        }
        if (connect_with_timeout(sockfd, 
                                 (struct sockaddr*)loaded_config.tcp_server[chosen_server], 
                                 sizeof(struct sockaddr), 
                                 GLOBAL_TIMEOUT
                                ) < 0) {
            LOG(LOG_ERR, "Failed to connect to upstream: %s\n", strerror(errno));
            close(sockfd);
            return NULL;
        }

        uint16_t head_length = htons(length);
        send(sockfd, (char*)&head_length, sizeof(uint16_t), 0);
        send(sockfd, query, length, 0);

        buffer = malloc(513 * sizeof(uint8_t));
        *recv_length = 0;
        recv(sockfd, buffer, 2, 0);
        *recv_length = ntohs(*(uint16_t*)buffer);

        *recv_length = recv(sockfd, buffer, *recv_length, 0);
        if (*recv_length < 20) {
            LOG(LOG_WARN, "Failed to receive answer from %s\n", raw_config.TCP_server[chosen_server]);
            close(sockfd);
            free(buffer);
            return NULL;
        }
        else {
            buffer[*recv_length] = 0;
            close(sockfd);
            return buffer;
        }
    }
}

struct dns_response *GetRecordPointerFromResponse(struct dns_response *response, int answer_count, int type) {

    if (answer_count > 0 && response) {
        for (int i = 0; i < answer_count; i++) {
            if (response[i].response_type == type)
                return &response[i];
        }
    }
    return NULL;
}