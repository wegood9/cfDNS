#include<sys/types.h>
#include<sys/socket.h>
#include<netinet/in.h>
#include<arpa/inet.h>
#include<stdlib.h>
#include<stdio.h>
#include<errno.h>
#include<string.h>


#include "config.h"
#include "socket.h"
#include "protocol.h"

void ArgParse(int argc,char *argv[]){
    preArgParse(argc,argv);
    if (isIPv6(raw_config.bind_ip)){
        struct sockaddr_in6 *listen=malloc(sizeof(struct sockaddr_in6));
        listen->sin6_port = htons(raw_config.bind_port);
        listen->sin6_family = AF_INET6;
        if (inet_pton(AF_INET6,raw_config.bind_ip,&listen->sin6_addr) <= 0){
            printf("Error: Wrong bind address\n");
            exit(errno);
        }
    }
    else{
        struct sockaddr_in *listen=malloc(sizeof(struct sockaddr_in));
        listen->sin_port = htons(raw_config.bind_port);
        listen->sin_family = AF_INET;
        if (inet_pton(AF_INET,raw_config.bind_ip,&listen->sin_addr) <= 0){
            printf("Error: Wrong bind address\n");
            exit(errno);
        }
    }
    loaded_config.listen = listen;
    int i = 0,j = 0;
    for (i = 0,j = 0; raw_config.UDP_server[i][0] && i < 8; i++){
        char *token_index = strtok(raw_config.UDP_server[i],":");
        loaded_config.udp_server[j]->sin_family = AF_INET;
        if(inet_pton(AF_INET, token_index, &loaded_config.udp_server[j]->sin_addr) <= 0)
            continue;
        loaded_config.udp_server[j]->sin_port = htons(atoi(strtok(NULL,":")));
        j++;
    }
    loaded_config.udp_num = j;

    for (i = 0,j = 0; raw_config.TCP_server[i][0] && i < 8; i++){
        char *token_index = strtok(raw_config.TCP_server[i],":");
        loaded_config.tcp_server[j]->sin_family = AF_INET;
        if(inet_pton(AF_INET, token_index, &loaded_config.tcp_server[j]->sin_addr) <= 0)
            continue;
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
}

void preArgParse(int argc,char *argv[]){

    FILE *fp = NULL;
    if (argc == 1) {
        printf("Reading config from default config.txt\n");
        fp = fopen("config.txt", "r");
    }
    else{
        printf("Reading config from %s\n",argv[1]);
        fp = fopen(argv[1], "r");
    }

    if (!fp){
        int errnum = errno;
        fprintf(stderr, "Error: failed to open config file: %s\n", strerror(errnum));
        exit(errno);
    }

    char tmp[256];
    
    strncpy(raw_config.bind_ip, ReadLine(fp, "bind_ip", tmp), 41);
    puts(raw_config.bind_ip);
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
    printf("Config loaded\n");
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
    printf("Error: missing config value \"%s\"\n", str);
    exit(EXIT_FAILURE);
    return NULL;
}

