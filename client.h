static bool inc(char **buffer_p, char *packet_end, int bytes);
extern struct dns_response *ParseDnsResponse(void *packet_buffer, 
					int packet_length, 
					int expected_id, 
					const char *domain_name, 
					int *answer_count);