#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>

#define GLOBAL_TIMEOUT 3000

extern bool isIPv6(char *ip_addr);
extern int connect_with_timeout(int sockfd, const struct sockaddr *addr, socklen_t addrlen, unsigned int timeout_ms);
extern unsigned GetScopeForIp(const char *ip);
