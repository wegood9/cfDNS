#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stdio.h>

struct _raw_config
{
    char bind_ip[41];
    char UDP_server[8][41];
    char TCP_server[8][41];
    char DoT_server[8][41];
    char DoH_server[8][41];
    FILE *hosts;
    char *cf_IP_range[100];
    unsigned bind_port;
    unsigned char debug_level;
    unsigned char cf_IP_version;
    unsigned char ttl_multiplier;
    char cf_IP[16][41];
    bool enable_AAAA,enable_mem_cache,enable_cfDNS;
};

struct config
{
    struct sockaddr_storage *listen;
    struct sockaddr_storage *udp_server[8];
    struct sockaddr_storage *tcp_server[8];
    short udp_num,tcp_num,dot_num,doh_num;
};

extern bool enable_cfDNS;
extern bool enable_mem_cache;
extern unsigned char debug_level;
extern struct _raw_config raw_config;
extern struct config loaded_config;
extern unsigned char ttl_multiplier;
extern struct trieNode *hosts_trie;

static void preArgParse(int argc,char *argv[]);
static char *ReadLine(FILE *fp, char str[], char *readin);
extern void ArgParse(int argc,char *argv[]);