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
#include "cache.h"

struct _raw_config raw_config;
struct config loaded_config;
unsigned char debug_level = 0;
struct trieNode *hosts_trie = NULL;
struct dns_cache *cache = NULL;

void ArgParse(int argc,char *argv[]){
    preArgParse(argc,argv);
    struct sockaddr_storage *listen_addr = malloc(sizeof(struct sockaddr_storage));;

    if (isValidIPv6(raw_config.bind_ip)){
        memset(listen_addr, 0, sizeof(struct sockaddr_storage));
        ((struct sockaddr_in6 *)listen_addr)->sin6_scope_id = GetScopeForIp(raw_config.bind_ip);
        ((struct sockaddr_in6 *)listen_addr)->sin6_port = htons(raw_config.bind_port);
        ((struct sockaddr_in6 *)listen_addr)->sin6_family = AF_INET6;
        if (inet_pton(AF_INET6,raw_config.bind_ip,&(((struct sockaddr_in6 *)listen_addr)->sin6_addr.s6_addr)) <= 0){
            LOG(LOG_FATAL, "Wrong binding address\n");
            exit(errno);
        }
    }
    else{
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
    for (i = 0,j = 0; raw_config.UDP_server[i][0] && i < MAX_SERVER_NUM_PER_TYPE; i++){
        char *token_index = strtok(raw_config.UDP_server[i], ":");
        if (!loaded_config.udp_server[j])
            loaded_config.udp_server[j] = malloc(sizeof(struct sockaddr_storage));
        
        // 读入IPv6地址格式
        if (token_index[strlen(token_index) - 1] == ']') {
            //去掉头尾的中括号
            token_index[strlen(token_index) - 1] = 0;
            token_index++;
            if(inet_pton(AF_INET6, token_index, &(((struct sockaddr_in6 *)loaded_config.udp_server[j])->sin6_addr) ) <= 0)
                continue;
            ((struct sockaddr_in6 *)loaded_config.udp_server[j])->sin6_port = htons(atoi(strtok(NULL, ":")));
            ((struct sockaddr_in6 *)loaded_config.udp_server[j])->sin6_family = AF_INET6;
        }
        else {
            //读入IPv4地址格式
            if(inet_pton(AF_INET, token_index, &(((struct sockaddr_in *)loaded_config.udp_server[j])->sin_addr) ) <= 0)
                continue;
            ((struct sockaddr_in *)loaded_config.udp_server[j])->sin_port = htons(atoi(strtok(NULL, ":")));
            ((struct sockaddr_in *)loaded_config.udp_server[j])->sin_family = AF_INET;
        }
        j++;
    }
    loaded_config.udp_num = j;

    for (i = 0,j = 0; raw_config.TCP_server[i][0] && i < MAX_SERVER_NUM_PER_TYPE; i++){
        char *token_index = strtok(raw_config.TCP_server[i], ":");
        if (!loaded_config.tcp_server[j])
            loaded_config.tcp_server[j] = malloc(sizeof(struct sockaddr_storage));
        
        // 读入IPv6地址格式
        if (token_index[strlen(token_index) - 1] == ']') {
            //去掉头尾的中括号
            token_index[strlen(token_index) - 1] = 0;
            token_index++;
            if(inet_pton(AF_INET6, token_index, &(((struct sockaddr_in6 *)loaded_config.tcp_server[j])->sin6_addr) ) <= 0)
                continue;
            ((struct sockaddr_in6 *)loaded_config.tcp_server[j])->sin6_port = htons(atoi(strtok(NULL, ":")));
            ((struct sockaddr_in6 *)loaded_config.tcp_server[j])->sin6_family = AF_INET6;
        }
        else {
            //读入IPv4地址格式
            if(inet_pton(AF_INET, token_index, &(((struct sockaddr_in *)loaded_config.tcp_server[j])->sin_addr) ) <= 0)
                continue;
            ((struct sockaddr_in *)loaded_config.tcp_server[j])->sin_port = htons(atoi(strtok(NULL, ":")));
            ((struct sockaddr_in *)loaded_config.tcp_server[j])->sin_family = AF_INET;
        }
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


    debug_level = raw_config.debug_level;

    if (raw_config.enable_mem_cache)
        cache = InitCache();

    if (raw_config.enable_cfDNS) {
        loaded_config.cf_IP_version = isValidIPv6(raw_config.cf_IP) ? 6 : 4;
        switch (loaded_config.cf_IP_version) {
        case 4:
            loaded_config.cf_IPv4 = inet_addr(raw_config.cf_IP);
            break;
        case 6:
            inet_pton(AF_INET6, raw_config.cf_IP, &loaded_config.cf_IPv6);
        default:
            break;
        }

        for (i = 0, j = 0; raw_config.cf_IPv4_range[i][0] && i < MAX_CF_IP_RANGE; i++) {
            char *token_index = strtok(raw_config.cf_IPv4_range[i], "/");
            if (!loaded_config.cf_IPv4_range[j])
                loaded_config.cf_IPv4_range[j] = malloc(sizeof(struct sockaddr_storage));
            if(inet_pton(AF_INET, token_index, &(loaded_config.cf_IPv4_range[j]->ip4)) <= 0)
                continue;
            loaded_config.cf_IPv4_range[j]->bits = atoi(strtok(NULL, "/"));
            j++;
        }
        loaded_config.cf4_num = j;

        for (i = 0, j = 0; raw_config.cf_IPv6_range[i][0] && i < MAX_CF_IP_RANGE; i++) {
            char *token_index = strtok(raw_config.cf_IPv6_range[i], "/");
            if (!loaded_config.cf_IPv6_range[j])
                loaded_config.cf_IPv6_range[j] = malloc(sizeof(struct sockaddr_storage));
            if(inet_pton(AF_INET6, token_index, &(loaded_config.cf_IPv6_range[j]->ip6)) <= 0)
                continue;
            loaded_config.cf_IPv6_range[j]->bits = atoi(strtok(NULL, "/"));
            j++;
        }
        loaded_config.cf6_num = j;
    }

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

    char tmp[512];
    
    strncpy(raw_config.bind_ip, ReadLine(fp, "bind_ip", tmp), MAX_IP_CHAR);
    raw_config.bind_port = atoi(ReadLine(fp, "bind_port", tmp));
    raw_config.hosts = fopen(ReadLine(fp, "hosts_file", tmp), "r");
    raw_config.enable_AAAA = ReadLine(fp, "enable_AAAA", tmp)[0] - 48;
    raw_config.enable_mem_cache = ReadLine(fp, "enable_mem_cache", tmp)[0] - 48;
    raw_config.cache_size = atoi(ReadLine(fp, "cache_size", tmp));
    raw_config.ttl_multiplier = atoi(ReadLine(fp, "ttl_multiplier", tmp));
    raw_config.min_cache_ttl = atoi(ReadLine(fp, "min_cache_ttl", tmp));
    raw_config.debug_level = ReadLine(fp, "debug", tmp)[0] - 48;
    raw_config.bind_tcp = ReadLine(fp, "bind_tcp", tmp)[0] - 48;

    char *token_index=strtok(ReadLine(fp, "UDP_server", tmp), ", ");
    for (unsigned char i = 0; token_index && i < MAX_SERVER_NUM_PER_TYPE; i++){
        if (i < MAX_SERVER_NUM_PER_TYPE - 1)
            raw_config.UDP_server[i+1][0] = 0; //may be removed
        if (strlen(token_index) > 6)
            strncpy(raw_config.UDP_server[i], token_index, 41);
        token_index=strtok(NULL, ", ");
    }

    token_index=strtok(ReadLine(fp, "TCP_server", tmp), ", ");
    for (unsigned char i = 0; token_index && i < MAX_SERVER_NUM_PER_TYPE; i++){
        if (i < MAX_SERVER_NUM_PER_TYPE - 1)
            raw_config.TCP_server[i+1][0] = 0; //may be removed
        if (strlen(token_index) > 6)
            strncpy(raw_config.TCP_server[i], token_index, 41);
        token_index=strtok(NULL, ", ");
    }

    token_index=strtok(ReadLine(fp, "DoH_server", tmp), "\", ");
    for (unsigned char i = 0; token_index && i < MAX_SERVER_NUM_PER_TYPE; i++){
        if (i < MAX_SERVER_NUM_PER_TYPE - 1)
            raw_config.DoH_server[i+1][0] = 0; //may be removed
        if (strlen(token_index) > 6)
            strncpy(raw_config.DoH_server[i], token_index, 41);
        token_index=strtok(NULL, "\", ");
    }

    token_index=strtok(ReadLine(fp, "DoT_server", tmp), "\", ");
    for (unsigned char i = 0; token_index && i < MAX_SERVER_NUM_PER_TYPE; i++){
        if (i < MAX_SERVER_NUM_PER_TYPE - 1)
            raw_config.DoT_server[i+1][0] = 0; //may be removed
        if (strlen(token_index) > 6)
            strncpy(raw_config.DoT_server[i], token_index, 41);
        token_index=strtok(NULL, "\", ");
    }

    raw_config.enable_cfDNS = atoi(ReadLine(fp, "enable_cfDNS", tmp));
    if (raw_config.enable_cfDNS) {
        strncpy(raw_config.cf_IP, ReadLine(fp, "cf_IP", tmp), MAX_IP_CHAR);
        token_index=strtok(ReadLine(fp, "cf_IPv4_range", tmp), "\", ");
        for (unsigned char i = 0; token_index && i < MAX_CF_IP_RANGE; i++){
            if (i < MAX_CF_IP_RANGE - 1)
                raw_config.cf_IPv4_range[i+1][0] = 0; //may be removed
            if (strlen(token_index) > 6)
                strncpy(raw_config.cf_IPv4_range[i], token_index, MAX_IP_CHAR);
            token_index=strtok(NULL, "\", ");
        }

        token_index=strtok(ReadLine(fp, "cf_IPv6_range", tmp), "\", ");
        for (unsigned char i = 0; token_index && i < MAX_CF_IP_RANGE; i++){
            if (i < MAX_CF_IP_RANGE - 1)
                raw_config.cf_IPv6_range[i+1][0] = 0; //may be removed
            if (strlen(token_index) > 6)
                strncpy(raw_config.cf_IPv6_range[i], token_index, MAX_IP_CHAR);
            token_index=strtok(NULL, "\", ");
        }
    }
    LOG(LOG_INFO, "Config loaded\n");
    close(fp);
}

char *ReadLine(FILE *fp, char str[], char *readin){
    rewind(fp);
    while(fgets(readin, 511, fp)){
        if (readin[0] == '#' || readin[0] == '\n')
            continue;
        if (!strncmp(readin, str, strlen(str))){
            if (readin[strlen(readin) - 1] == '\n')
                readin[strlen(readin) - 1] = 0; //去掉换行

            for (int i = 0; i < strlen(readin); i++)
                if (readin[i] == ' ')
                    return readin+i+1;
        }
    }
    LOG(LOG_FATAL, "Missing config value \"%s\"\n", str);
    exit(EXIT_FAILURE);
    return NULL;
}

