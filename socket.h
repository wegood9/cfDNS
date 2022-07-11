#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>

#define GLOBAL_TIMEOUT 3000

extern int connect_with_timeout(int sockfd, const struct sockaddr *addr, socklen_t addrlen, unsigned int timeout_ms);
extern int MyBind(const char *ip, const char *port, int type);