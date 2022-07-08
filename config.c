#include<sys/types.h>
#include<sys/socket.h>
#include<netinet/in.h>
#include<arpa/inet.h>
#include<stdlib.h>
#include<stdio.h>
#include<errno.h>
#include<string.h>

#include "debug.h"
#include "config.h"
#include "socket.h"
#include "protocol.h"

struct _raw_config raw_config;
struct config loaded_config;
bool enable_cfDNS;
bool enable_mem_cache;
unsigned char debug_level;

void ArgParse(int argc,char *argv[]){
    preArgParse(argc,argv);
    void *listen_addr;

    if (isValidIPv6(raw_config.bind_ip)){
        listen_addr = (struct sockaddr_in6 *)malloc(sizeof(struct sockaddr_in6));
        memset(listen_addr, 0, sizeof(struct sockaddr_in6));
        ((struct sockaddr_in6 *)listen_addr)->sin6_port = htons(raw_config.bind_port);
        ((struct sockaddr_in6 *)listen_addr)->sin6_family = AF_INET6;
        if (inet_pton(AF_INET6,raw_config.bind_ip,&((struct sockaddr_in6 *)listen_addr)->sin6_addr) <= 0){
            LOG(LOG_FATAL, "Wrong binding address\n");
            exit(errno);
        }
    }
    else{
        listen_addr = (struct sockaddr_in *)malloc(sizeof(struct sockaddr_in));
        memset(listen_addr, 0, sizeof(struct sockaddr_in));
        ((struct sockaddr_in *)listen_addr)->sin_port = htons(raw_config.bind_port);
        ((struct sockaddr_in *)listen_addr)->sin_family = AF_INET;
        void *sin_addr = &(((struct sockaddr_in *)listen_addr)->sin_addr);
        if (inet_pton(AF_INET,raw_config.bind_ip,sin_addr) <= 0){
            LOG(LOG_FATAL, "Wrong binding address\n");
            exit(errno);
        }
    }
    loaded_config.listen = listen_addr;
    int i = 0,j = 0;
    for (i = 0,j = 0; raw_config.UDP_server[i][0] && i < 8; i++){
        char *token_index = strtok(raw_config.UDP_server[i],":");
        if (!loaded_config.udp_server[j])
            loaded_config.udp_server[j] = malloc(sizeof(loaded_config.udp_server[j]));

        if(inet_pton(AF_INET, token_index, &loaded_config.udp_server[j]->sin_addr) <= 0)
            continue;

        loaded_config.udp_server[j]->sin_port = htons(atoi(strtok(NULL,":")));
        loaded_config.udp_server[j]->sin_family = AF_INET;
        j++;
    }
    loaded_config.udp_num = j;

    for (i = 0,j = 0; raw_config.TCP_server[i][0] && i < 8; i++){
        char *token_index = strtok(raw_config.TCP_server[i],":");
        if (!loaded_config.tcp_server[j])
            loaded_config.tcp_server[j] = malloc(sizeof(loaded_config.tcp_server[j]));

        if(inet_pton(AF_INET, token_index, &loaded_config.tcp_server[j]->sin_addr) <= 0)
            continue;
        
        loaded_config.tcp_server[j]->sin_family = AF_INET;
        loaded_config.tcp_server[j]->sin_port = htons(atoi(strtok(NULL,":")));
        j++;
    }
    loaded_config.tcp_num = j;

    i = 0;
    while(raw_config.DoH_server[i][0])
        i++;
    loaded_config.doh_num = i;
    i = 0;
    while(raw_config.DoT_server[i][0])
        i++;
    loaded_config.dot_num = i;

    enable_cfDNS = raw_config.enable_cfDNS;
    enable_mem_cache = raw_config.enable_mem_cache;
    debug_level = raw_config.debug_level;
}

void preArgParse(int argc,char *argv[]){

    FILE *fp = NULL;
    if (argc == 1) {
        LOG(LOG_INFO, "Reading config from default config.txt\n");
        fp = fopen("config.txt", "r");
    }
    else{
        LOG(LOG_INFO, "Reading config from %s\n",argv[1]);
        fp = fopen(argv[1], "r");
    }

    if (!fp){
        int errnum = errno;
        LOG(LOG_FATAL, "Failed to open config file: %s\n", strerror(errnum));
        exit(errno);
    }

    char tmp[256];
    
    strncpy(raw_config.bind_ip, ReadLine(fp, "bind_ip", tmp), 41);
    raw_config.bind_port = atoi(ReadLine(fp, "bind_port", tmp));
    raw_config.hosts = fopen(ReadLine(fp, "hosts_file", tmp), "r");
    raw_config.enable_AAAA = ReadLine(fp, "enable_AAAA", tmp)[0] - 48;
    raw_config.enable_mem_cache = ReadLine(fp, "enable_mem_cache", tmp)[0] - 48;
    raw_config.debug_level = ReadLine(fp, "debug", tmp)[0] - 48;

    char *token_index=strtok(ReadLine(fp, "UDP_server", tmp), ", ");
    for (unsigned char i = 0; token_index && i < 8; i++){
        if (i < 7)
            raw_config.UDP_server[i+1][0] = 0; //may be removed
        if (strlen(token_index) > 6)
            strncpy(raw_config.UDP_server[i], token_index, 41);
        token_index=strtok(NULL, ", ");
    }

    token_index=strtok(ReadLine(fp, "TCP_server", tmp), ", ");
    for (unsigned char i = 0; token_index && i < 8; i++){
        if (i < 7)
            raw_config.TCP_server[i+1][0] = 0; //may be removed
        if (strlen(token_index) > 6)
            strncpy(raw_config.TCP_server[i], token_index, 41);
        token_index=strtok(NULL, ", ");
    }

    token_index=strtok(ReadLine(fp, "DoH_server", tmp), "\", ");
    for (unsigned char i = 0; token_index && i < 8; i++){
        if (i < 7)
            raw_config.DoH_server[i+1][0] = 0; //may be removed
        if (strlen(token_index) > 6)
            strncpy(raw_config.DoH_server[i], token_index, 41);
        token_index=strtok(NULL, "\", ");
    }

    token_index=strtok(ReadLine(fp, "DoT_server", tmp), "\", ");
    for (unsigned char i = 0; token_index && i < 8; i++){
        if (i < 7)
            raw_config.DoT_server[i+1][0] = 0; //may be removed
        if (strlen(token_index) > 6)
            strncpy(raw_config.DoT_server[i], token_index, 41);
        token_index=strtok(NULL, "\", ");
    }

    raw_config.enable_cfDNS = atoi(ReadLine(fp, "enable_cfDNS", tmp));
    if (raw_config.enable_cfDNS){
        raw_config.cf_IP_version = atoi(ReadLine(fp, "cf_IP_version", tmp));
        strncpy(raw_config.cf_IP, ReadLine(fp, "cf_IP", tmp), 41);
        token_index=strtok(ReadLine(fp, "cf_IP_range", tmp), "\", ");
        for (unsigned char i = 0; token_index && i < 16; i++){
            if (i < 15)
                raw_config.cf_IP_range[i+1][0] = 0; //may be removed
            if (strlen(token_index) > 6)
                strncpy(raw_config.cf_IP_range[i], token_index, 41);
            token_index=strtok(NULL, "\", ");
        }
    }
    LOG(LOG_INFO, "Config loaded\n");
    close(fp);
}

char *ReadLine(FILE *fp, char str[], char *readin){
    rewind(fp);
    while(fgets(readin,256,fp)){
        if (readin[0] == '#' || readin[0] == '\n')
            continue;
        if (!strncmp(readin, str, strlen(str))){
            readin[strlen(readin) - 1] = 0;
            for (int i = 0; i < strlen(readin); i++)
                if (readin[i] == ' ')
                    return readin+i+1;
        }
    }
    LOG(LOG_FATAL, "Missing config value \"%s\"\n", str);
    exit(EXIT_FAILURE);
    return NULL;
}

