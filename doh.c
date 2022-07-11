#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>

#include "server.h"
#include "config.h"
#include "debug.h"
#include "dnspacket.h"


char *QueryDoH(const char *domain_name, 
			int *packet_size, 
			int request_id, 
			int request_q_type) {

    FILE *fp;
    char buffer[512];
    char *token, *answer = NULL;
    void *tmp;
    int chosen = rand() % loaded_config.doh_num;
    char query[256] = "curl -s ";
    uint32_t ttl = 0;
    uint32_t answer_ip4;
    __uint128_t answer_ip6;


    sprintf(query, "curl -m 3 -s \"%s?name=%s&type=%s\"", raw_config.DoH_server[chosen], domain_name, request_q_type == DNS_A_RECORD ? "A" : "AAAA");
    fp=popen(query,"r");


    fgets(buffer, sizeof(buffer), fp);
    if(strlen(buffer) < 5) {
        LOG(LOG_INFO, "DoH query timed out\n");
        return NULL;
    }

    token = strstr(buffer, "{\"Status\":");

    if (!token) {
        LOG(LOG_WARN, "DoH query failed\n");
        return NULL;
    }

    token += strlen("{\"Status\":");

    int status = atoi(token);
    switch (status) {
        case 0:
            token = strstr(token, "\"Answer\"");
            if (!token) {
                LOG(LOG_WARN, "DoH query failed\n");
                break;
            }
            token = strstr(token, request_q_type == DNS_A_RECORD ? "\"type\":1," : "\"type\":28,");
            if (!token) {
                LOG(LOG_WARN, "DoH query failed\n");
                break;
            }
            token = strstr(token, "\"TTL\":");
            token += strlen("\"TTL\":");
            ttl = atoi(token);
            token = strstr(token, "\"data\":\"");
            token += strlen("\"data\":\"");
            token = strtok(token, "\"");
            if (request_q_type == DNS_A_RECORD) {
                answer_ip4 = inet_addr(token);
                tmp = &answer_ip4;
            }
            else {
                inet_pton(AF_INET6, token, &answer_ip6);
                tmp = &answer_ip6;
            }
            LOG(LOG_DBG, "IP: %s\n", token);
            answer = BuildDnsResponsePacket(domain_name, packet_size, request_id, request_q_type, tmp, ttl);
            break;
        case 3:
            answer = BuildDnsResponsePacket(domain_name, packet_size, request_id, request_q_type, NULL, ttl);
            break;
        default:
            LOG(LOG_WARN, "DoH query failed\n");
            break;
    }
    
    pclose(fp);
    return answer;
}
