#include<stdbool.h>
#include<stdlib.h>
#include<stdio.h>
#include<string.h>
#include<netinet/in.h>
#include<stdint.h>

#include "debug.h"
#include "protocol.h"
#include "config.h"
#include "client.h"


static struct dns_request *ParseDnsQuery(void *received_packet_buffer, int received_packet_length, int *q_count);
void *BuildDnsResponsePacket(const char *domain_name, 
                             int *packet_size, 
			                 const uint16_t request_id, 
                             const int response_q_type, 
                             const void *answer_in, 
                             const uint32_t ttl);
void ProcessDnsQuery(const int client_fd, 
                     const struct sockaddr *client_addr, 
                     void *received_packet_buffer, 
                     int received_packet_length);

static void ModifyID(void *buffer, uint16_t id);