#include<stdbool.h>
#include<stdlib.h>
#include<stdio.h>
#include<string.h>
#include<netinet/in.h>
#include<stdint.h>

#include "debug.h"
#include "dnspacket.h"
#include "protocol.h"

#define MAX_AN_COUNT 50

void *build_dns_request_packet(const char *domain_name, int *packet_size, 
			       int *request_id, int request_q_type) {

    struct dns_header *header;
    struct dns_query_trailer *q_trailer;
    size_t domain_length, question_size, total_size, token_length;
    char *buffer, *dnspacket, *token_index;
    char temp_buffer[MAX_DOMAIN_LENGTH + 1];

  /* Calculate the size of the DNS request packet, which is the size of the
     header plus the question section.
     The length of the question section is equal to the length of the domain
     name (where each period character is replaced by the length of the 
     subdomain) +1 to account for the last subdomain (e.g. www.google.com
     would become 3www6google3com). Then add +1 for the null root character
     and the remaining fields in the dns_question_trailer. */
    domain_length = strlen(domain_name);
    if (domain_length > MAX_DOMAIN_LENGTH) {
        LOG(LOG_WARN, "Queried name too long: %s\n", domain_name);
        return NULL;
    }

    question_size = domain_length + sizeof(struct dns_query_trailer) + 2; //最前的1字节和最后的root
    total_size = question_size + HEADER_SIZE;
    *packet_size = total_size;

  /* Allocate memory for the DNS packet buffer. */
    dnspacket = buffer = (char *)malloc(total_size);
    if (dnspacket == NULL) {
        LOG(LOG_ERR, "Failed to allocate memory when sending requests\n");
        return NULL;
    }

  /* Fill out the header struct for a DNS request and copy it into the packet 
     buffer. */
    *request_id = rand() % UINT16_MAX;
    header = (struct dns_header *)buffer;
    memset(&header, 0, HEADER_SIZE);
    header->id = htons(*request_id);
    header->flags = htons(DNS_USE_RECURSION);
    header->qd_count = htons(1);
    header->an_count = htons(0);
    header->ns_count = htons(0);
    header->ar_count = htons(0);

    buffer += HEADER_SIZE;

  /* Split up the domain name by the period character and copy each subdomain
     into the buffer, prefixed by the length of the subdomain. First copy the
     domain name into a temp buffer though so it can be manipulated without 
     affecting the original string. */
    strcpy(temp_buffer, domain_name);

    token_index = strtok(temp_buffer, ".");
    while (token_index != 0) {

    /* First copy the length into the buffer, then the rest of the string. The
       string is copied byte by byte to preserve the proper byte ordering. */
        token_length = strlen(token_index);

    /* Verify the subdomain length is less than max. Return if too large. */
        if (token_length > MAX_SUBDOMAIN_LENGTH) {
            LOG(LOG_WARN, "Queried name too long: %s\n", domain_name);
            free(dnspacket);
            return NULL;
        }

    /* Copy the string byte by byte. */
        *buffer++ = token_length;
        while ((*buffer++ = *token_index++) != 0);

    /* Move back a byte because we want to overwrite the null terminator
       when copying the next string. */
        buffer--;

        token_index = strtok(NULL, ".");
    }

  /* Mark the end with a zero length octet for the null label, then copy the 
     last few octets for the question part. */
    *buffer++ = 0;
    q_trailer = (struct dns_query_trailer *)buffer;
    q_trailer->q_type  = htons(request_q_type);
    q_trailer->q_class = htons(DNS_INET_ADDR);

    return dnspacket;
}


/* Validates the DNS response and returns an array of DNS response structures.
   Returns null if there was an error or if the domain name was not found.
   On an error, the error_message buffer will not be null. */
struct dns_response *parse_dns_response(void *packet_buffer, 
					int packet_length, 
					int expected_id, 
					const char *domain_name, 
					int *answer_count, 
					char *error_message) {

    int i, bytes_read, authoritative;
    char buffer[MAX_DOMAIN_LENGTH + 1];
    char *buffer_index, *packet_end;
    uint8_t reply_code;
    uint16_t rdata_length;
    struct dns_header header;
    struct dns_response *responses;

    authoritative = 0;
    *error_message = 0;
    *answer_count = 0;
  

  /* Verify that the packet is large enough to contain the DNS header, and
     then copy it into a dns_header struct. */
    if (packet_length < HEADER_SIZE) {
        LOG(LOG_INFO, "Rceiving an invalid DNS response\n");
        *answer_count = -1;
        return NULL; //丢弃
    }

  /* Use the buffer index to step through the packet, checking that it 
     doesn't extend past the packet_end value. */
    buffer_index = (char *)packet_buffer;
    packet_end = buffer_index + packet_length;

  /* When copying the header back, convert the values from network byte
     order to the host byte order. */
    memcpy(&header, buffer_index, HEADER_SIZE);
    buffer_index += HEADER_SIZE;

    header.id = ntohs(header.id);
    header.flags = ntohs(header.flags);
    header.qd_count = ntohs(header.qd_count);
    header.an_count = ntohs(header.an_count);
    header.ns_count = ntohs(header.ns_count);
    header.ar_count = ntohs(header.ar_count);

  /* Verify that the response ID is the same as the ID sent in the request. */
    if (header.id != expected_id) {
        LOG(LOG_INFO, "Response id does not match request id\n");
        *answer_count = -1;
        return NULL; //丢弃
    }

  /* Check the flags to verify that this is a valid response. */
    if (!(header.flags & DNS_IS_RESPONSE)) {
        LOG(LOG_INFO, "Header does not contain response flag\n");
        *answer_count = -1;
        return NULL; //丢弃
    }

  /* If the message was truncated, return an error. */
    if (header.flags & DNS_TRUNCATED) {
        LOG(LOG_WARN, "Response was truncated\n");
        return NULL; //！转发
    }

  /* If no recursion is available, return an error. */
    if (!(header.flags & DNS_RECURSION_AVAIL)) 
        return NULL; //！转发


    /* Check for error conditions. */
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
        /* A name error indicates that the name was not found. This isn't due to
       an error, so we just indicate that the number of answers is 0 and return
       a null value. */
            *answer_count = 0; //NXDOMAIN
        default:
            break;
        }
        return NULL; //！转发
    }

  /* Verify that there is at least one answer. We also put a limit on the number
     of answers allowed. This is to prevent a bogus response containing a very
     high answer count from allocating too much memory by setting an upper
     bound. */
    if (header.an_count < 1) { 
        *answer_count = 0;
        return NULL; //！转发
    }

    if (header.an_count > MAX_AN_COUNT){
        LOG(LOG_INFO, "Response contains too many answers\n");
        header.an_count = MAX_AN_COUNT; //响应中答案数量过多
    }

    //是否为权威响应
    if (header.flags & DNS_AUTH_ANS) 
        authoritative = 1;

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
  
  /* Answer section. There may be multiple answer sections which we can determine from
     the packet header. Allocate enough space for all of the buffers. 
     The first part of each answer section is similar to the question section, containing
     the name  that we queried for. Ignore this for now, maybe verify that it is the
     same name later. */
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
            responses[i].ip6_addr = ntohl(*(__uint128_t *)buffer_index);
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

    /* When we increment the buffer, we may move past the end of the packet at this
       point. This is OK only if this is the last answer we are processing. */
        if (!inc(&buffer_index, packet_end, rdata_length) && (i + 1 < header.an_count)) {
            free(responses);
	        LOG(LOG_INFO, "Receiving an invalid response\n");
            *answer_count = -1;
	        return NULL; //丢弃
        }
    }

    return responses;
}

/* Increments the buffer pointer by a number of bytes and checks that it is still
   below the max index value. Returns 0 if the new address is invalid, 1 otherwise. */
bool inc(char **buffer_p, char *packet_end, int bytes) {
    *buffer_p += bytes;
    return *buffer_p >= packet_end ? 0 : 1;
}