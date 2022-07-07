#include <stdio.h>
#include <stdlib.h>
#include <errno.h>

#include "config.h"

int main(int argc, char *argv[]){
    ArgParse(argc,argv);
    int listenfd, connfd, n;
    char *buffer;

    if ((listenfd = socket(AF_INET, SOCK_DGRAM, 0)) != -1 && 
        bind(listenfd, (struct sockaddr*)&loaded_config.listen, sizeof(loaded_config.listen)) != -1 &&
        listen(listenfd, 20) != -1)
        printf("Server is listening on UDP port %d at %s", raw_config.bind_port, raw_config.bind_port);
    else {
        printf("Error: failed to listen: %s\n",strerror(errno));
        exit(EXIT_FAILURE);
    }
    while (1) {
        if( (connfd = accept(listenfd, (struct sockaddr*)NULL, NULL)) == -1){
            printf("accept socket error: %s(errno: %d)",strerror(errno),errno);
            continue;
        }
        buffer = malloc(513*sizeof(u_int8_t));
        n = recv(connfd, buffer, 512, 0);
        buffer[n] = '\0';
        ProcessDnsQuery(connfd, buffer, n);
        close(connfd);
    }
    return 0;
}
