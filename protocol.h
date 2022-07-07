#include <arpa/inet.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

#include "dnspacket.h"

bool cidr_match(const struct in_addr *addr, const struct in_addr *net, uint8_t bits);
bool is_valid_ipv6(const char *ip);
bool is_valid_ipv4(const char *ip);
extern int ParseDomainName(char *packet_index, char *packet_start, int packet_size, char *dest_buffer);
extern bool inc(char **buffer_p, char *packet_end, int bytes);
extern char *LookupType(const int type);