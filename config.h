#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stdio.h>

#include "cache.h"

#define MAX_IP_CHAR 50
#define MAX_SERVER_NUM_PER_TYPE 8
#define MAX_CF_IP_RANGE 16

struct _raw_config
{
    char bind_ip[MAX_IP_CHAR + 1];
    char bind_port[6];
    char UDP_server[MAX_SERVER_NUM_PER_TYPE][MAX_IP_CHAR + 1];
    char TCP_server[MAX_SERVER_NUM_PER_TYPE][MAX_IP_CHAR + 1];
    char DoT_server[MAX_SERVER_NUM_PER_TYPE][100];
    char DoH_server[MAX_SERVER_NUM_PER_TYPE][100];
    FILE *hosts;
    char cf_IPv4_range[MAX_CF_IP_RANGE][20];
    char cf_IPv6_range[MAX_CF_IP_RANGE][MAX_IP_CHAR + 1];
    unsigned char debug_level;
    unsigned char ttl_multiplier;
    unsigned int cache_size;
    unsigned short min_cache_ttl;
    char cf_IP[MAX_IP_CHAR];
    bool enable_AAAA,enable_mem_cache,enable_cfDNS,bind_tcp;
};

struct config
{
    struct sockaddr_storage *udp_server[MAX_SERVER_NUM_PER_TYPE];
    struct sockaddr_storage *tcp_server[MAX_SERVER_NUM_PER_TYPE];
    struct cidr4 *cf_IPv4_range[MAX_CF_IP_RANGE];
    struct cidr6 *cf_IPv6_range[MAX_CF_IP_RANGE];
    short udp_num,tcp_num,dot_num,doh_num;
    __uint128_t cf_IPv6;
    uint32_t cf_IPv4;
    unsigned char cf4_num, cf6_num;
    unsigned char cf_IP_version;
};

struct cidr4
{
    uint32_t ip4; //网络序
    unsigned char bits;
};

struct cidr6
{
    struct in6_addr ip6;
    unsigned char bits;
};

extern unsigned char debug_level;
extern struct _raw_config raw_config;
extern struct config loaded_config;
extern struct trieNode *hosts_trie;
extern LRUCache *cache;


static void preArgParse(int argc,char *argv[]);
static char *ReadLine(FILE *fp, char str[], char *readin);
extern void ArgParse(int argc,char *argv[]);