#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>

#include "debug.h"
#include "server.h"
#include "hosts.h"


int main(int argc, char *argv[]){
    ArgParse(argc,argv);
    int listenfd, n;
    char *buffer;
    struct sockaddr client_sockaddr;
    int n_size = sizeof(struct sockaddr);

    hosts_trie = InitHosts(raw_config.hosts);
    if (!hosts_trie)
        LOG(LOG_WARN, "Failed to load hosts: %s\n", strerror(errno));
    else
        LOG(LOG_INFO, "hosts loaded\n");

    if ((listenfd = socket((struct sockaddr_storage*)loaded_config.listen->ss_family, SOCK_DGRAM, 0)) != -1 && 
        bind(listenfd, (struct sockaddr*)loaded_config.listen, sizeof(struct sockaddr)) != -1)
        LOG(LOG_WARN, "Server is listening on UDP port %d at %s\n", raw_config.bind_port, raw_config.bind_ip);
    else {
        LOG(LOG_FATAL, "Failed to bind: %s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }
    while (1) {
        buffer = malloc(513 * sizeof(u_int8_t));

        n = recvfrom(listenfd, buffer, 512, 0, (struct sockaddr*)&client_sockaddr, &n_size);
        if (n == -1)
            LOG(LOG_ERR, "Failed to receive request: %s\n", strerror(errno));
        buffer[n] = '\0';
        ProcessDnsQuery(listenfd, &client_sockaddr, buffer, n);
        
    }
    close(listenfd);
    return 0;
}
