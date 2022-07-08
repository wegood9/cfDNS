
#define DNS_IS_RESPONSE		0x8000
#define DNS_AUTH_ANS		0x0400
#define DNS_TRUNCATED		0x0200
#define DNS_USE_RECURSION	0x0100
#define DNS_RECURSION_AVAIL	0x0080
#define DNS_REPLY_CODE_MASK 0x000f

#define DNS_FORMAT_ERROR	0x0001
#define DNS_SERVER_FAILURE	0x0002
#define DNS_NAME_ERROR		0x0003
#define DNS_NOT_IMPLEMENTED	0x0004
#define DNS_REFUSED         0x0005

#define DNS_INET_ADDR       0x0001
//type
#define DNS_AAAA_RECORD     0x001c
#define DNS_A_RECORD		0x0001
#define DNS_NS_RECORD		0x0002
#define DNS_CNAME_RECORD	0x0005
#define DNS_MX_RECORD		0x000f
#define DNS_SOA_RECORD      0x0006

#define MAX_DOMAIN_LENGTH 255
#define MAX_SUBDOMAIN_LENGTH 63

#define HEADER_SIZE 12

#define DNS_POINTER_FLAG	0xc0
#define DNS_POINTER_OFFSET_MASK 0x3fff
#define DNS_LABEL_LENGTH_MASK	0x3f



struct dns_header {
    uint16_t id;
    uint16_t flags;
    uint16_t qd_count; //问题计数
    uint16_t an_count; //直接回答计数
    uint16_t ns_count; //权威计数
    uint16_t ar_count; //额外信息计数
};

struct dns_query_trailer {
    uint16_t q_type;
    uint16_t q_class;
};

struct dns_response {
    uint16_t response_type;
    uint16_t preference; //MX 记录
    uint32_t cache_time; //ttl
    uint32_t ip_addr; //ipv4 地址
    __uint128_t ip6_addr; //ipv6 地址
    char name[MAX_DOMAIN_LENGTH + 1]; // CNAME, MX, NS，TXT 等使用
    uint8_t authoritative; //权威响应
};

struct dns_request {
    uint32_t src_ip_addr; //ipv4 地址
    __uint128_t src_ip6_addr; //ipv6 地址
    uint16_t id;
    uint16_t q_type;
    char name[MAX_DOMAIN_LENGTH + 1];
};

struct dns_rr_trailer_A
{
    uint16_t rr_domain_pointer;
    uint16_t rr_type;
    uint16_t rr_class;
    uint32_t rr_ttl;
    uint16_t rdata_length;
    uint32_t ip_addr;
};

struct dns_rr_trailer_AAAA
{
    uint16_t rr_domain_pointer;
    uint16_t rr_type;
    uint16_t rr_class;
    uint32_t rr_ttl;
    uint16_t rdata_length;
    __uint128_t ip6_addr;
};
