#include <stdbool.h>
#include <string.h>
#include <netinet/in.h>
#include <errno.h>

#include "socket.h"
#include "config.h"

bool isIPv6(char *ip_addr){
    if (ip_addr[0] == '[' || (!strrchr(ip_addr, ':') && strrchr(ip_addr, ':') != !strchr(ip_addr, ':')) )
        return true;
    else
        return false;
}

int listen(){
    int listenfd;
    if ((listenfd = socket(AF_INET, SOCK_DGRAM, 0)) != -1 && 
        bind(listenfd, (struct sockaddr*)&loaded_config.listen, sizeof(loaded_config.listen)) != -1 &&
        listen(listenfd, 10) != -1)
        printf("Server is listening on UDP port %d at %s", raw_config.bind_port, raw_config.bind_port);
    else{
        printf("Error: failed to listen: %s\n",strerror(errno));
        exit(EXIT_FAILURE);
    }
    return listenfd;
}