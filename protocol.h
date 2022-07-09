#include <arpa/inet.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

#include "dnspacket.h"

#define DEFAULT_TTL 3600

extern bool cidr_match(const struct in_addr *addr, const struct in_addr *net, uint8_t bits);
extern bool cidr6_match(const struct in6_addr *address, const struct in6_addr *network, uint8_t bits);
extern bool isValidIPv6(const char *ip);
extern bool isValidIPv4(const char *ip);
extern int ParseDomainName(char *packet_index, char *packet_start, int packet_size, char *dest_buffer);
extern bool inc(char **buffer_p, char *packet_end, int bytes);
extern char *LookupType(const int type);