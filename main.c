#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>

#include "config.h"
#include "debug.h"

int main(int argc, char *argv[]){
    ArgParse(argc,argv);
    int listenfd, n;
    char *buffer;
    struct sockaddr client_sockaddr;
    

    if ((listenfd = socket((struct sockaddr_storage*)loaded_config.listen->ss_family, SOCK_DGRAM, 0)) != -1 && 
        bind(listenfd, (struct sockaddr*)loaded_config.listen, sizeof(struct sockaddr)) != -1)
        LOG(LOG_WARN, "Server is listening on UDP port %d at %s", raw_config.bind_port, raw_config.bind_ip);
    else {
        LOG(LOG_FATAL, "Failed to bind: %s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }
    while (1) {
        buffer = malloc(513 * sizeof(u_int8_t));

        n = recvfrom(listenfd, buffer, 512, 0, &client_sockaddr, &n_size);
        buffer[n] = '\0';
        ProcessDnsQuery(listenfd, &client_sockaddr, buffer, n);
        
    }
    close(listenfd);
    return 0;
}
