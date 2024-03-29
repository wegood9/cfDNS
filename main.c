#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>

#include "server.h"
#include "debug.h"
#include "config.h"
#include "protocol.h"
#include "hosts.h"

struct param {
    int listenfd;  
    int n;
    struct sockaddr_storage *client_sockaddr;
    char *buffer;
};

void *client_thread(void *arg);
void *tcp_server_thread(void);

int main(int argc, char *argv[] ){
    ArgParse(argc,argv);
    int listenfd, n;
    char *buffer;
    struct sockaddr_storage *client_sockaddr;
    struct param *para;
    socklen_t n_size = sizeof(struct sockaddr_storage);

    hosts_trie = InitHosts(raw_config.hosts);
    if (!hosts_trie)
        LOG(LOG_ERR, "Failed to load hosts: %s\n", strerror(errno));
    else
        LOG(LOG_INFO, "hosts loaded\n");

    if (loaded_config.doh_num)
        LOG(LOG_WARN, "DoH settings detected! Put DoH upstream first\n");

    listenfd = MyBind(raw_config.bind_ip, raw_config.bind_port, SOCK_DGRAM);

    if (pthread_mutex_init(&cache_lock, NULL)) {
        LOG(LOG_FATAL, "Failed to create lock\n");
        exit(EXIT_FAILURE);
    }

    if (raw_config.bind_tcp) {
        pthread_t tcp;
        pthread_create(&tcp, NULL, tcp_server_thread, NULL);
    }

    while (1) {
        buffer = malloc(513 * sizeof(u_int8_t));
        client_sockaddr = malloc(sizeof(struct sockaddr_storage));
        para = malloc(sizeof(struct param));
    
        n = recvfrom(listenfd, buffer, 512, 0, client_sockaddr, &n_size);
        if (n == -1) {
            LOG(LOG_ERR, "Failed to receive request: %s\n", strerror(errno));
            free(n);
            free(buffer);
            free(client_sockaddr);
            free(para);
            continue;
        }
        buffer[n] = '\0';
        para->listenfd = listenfd;
        para->buffer = buffer;
        para->client_sockaddr = client_sockaddr;
        para->n = n;

        pthread_t t;
        pthread_attr_t a; //线程属性
        pthread_attr_init(&a); //初始化线程属性
        pthread_attr_setdetachstate(&a, PTHREAD_CREATE_DETACHED); //设置线程属性
        pthread_create(&t, &a, client_thread, (void*)para);
        
    }
    close(listenfd);
    return 0;
}

void *client_thread(void *arg) {
    struct param *para = (struct param *)arg;
    ProcessDnsQuery(para->listenfd, para->client_sockaddr, para->buffer, para->n);
    free(para->buffer);
    free(para->client_sockaddr);
    free(arg);
    return NULL;
}

void *tcp_server_thread(void) {
    char buffer[4096];
    uint16_t n;
    int listenfd, connfd, sendfd;

    int chosen_server;

    if (!loaded_config.tcp_num) {
        LOG(LOG_ERR, "No TCP upstream server found\n");
        LOG(LOG_ERR, "Ignore bind_tcp\n");
        return NULL;
    }

    listenfd = MyBind(raw_config.bind_ip, raw_config.bind_port, SOCK_STREAM);
    listen(listenfd, 16);

    while (1) {

        if( (connfd = accept(listenfd, (struct sockaddr_storage*)NULL, NULL)) == -1){
            LOG(LOG_ERR, "Accept socket error: %s(errno: %d)\n",strerror(errno),errno);
            continue;
        }
        n = recv(connfd, buffer, 2, 0);
        n = *(uint16_t*)buffer; //网络序
        n = recv(connfd, &buffer[2], ntohs(n), 0);
        if (n < 20) {
            close(connfd);
            LOG(LOG_WARN, "Received invaild TCP DNS request\n");
            continue;
        }
        else
            LOG(LOG_INFO, "Received a TCP DNS request\n");

        chosen_server = rand() % loaded_config.tcp_num;
        if ((sendfd = socket(loaded_config.tcp_server[chosen_server]->ss_family, SOCK_STREAM, 0)) < 0) {
            LOG(LOG_ERR, "Failed to create socket: %s\n", strerror(errno));
            close(sendfd);
            continue;
        }
        if (connect_with_timeout(sendfd, 
                                 (struct sockaddr_storage*)loaded_config.tcp_server[chosen_server], 
                                 sizeof(struct sockaddr_storage), 
                                 GLOBAL_TIMEOUT
                                ) < 0) {
            LOG(LOG_ERR, "Failed to connect to TCP upstream: %s\n", strerror(errno));
            close(sendfd);
            close(connfd);
            return NULL;
        }

        send(sendfd, buffer, n + 2, 0);

        recv(sendfd, buffer, 2, 0);
        n = *(uint16_t*)buffer;
        n = recv(sendfd, &buffer[2], ntohs(n), 0);

        send(connfd, buffer, n + 2, 0);
        close(sendfd);
        close(connfd);
    }
    return NULL;
}