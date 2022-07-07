extern struct dns_response *ParseDnsResponse(void *packet_buffer, 
					int packet_length, 
					int expected_id, 
					const char *domain_name, 
					int *answer_count);
extern void *BuildDnsRequestPacket(const char *domain_name, int *packet_size, 
			       int *request_id, int request_q_type);
extern char *SendDnsRequest(char *query, int length, int *recv_length);