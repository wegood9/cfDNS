#include <stdint.h>


//37个不同字符：数字、字母和点
#define CHARS 37

struct trieNode
{
    bool isLeaf;
    uint32_t ip4; //存入即为网络序
    __uint128_t ip6;
    struct trieNode *child[CHARS];
};

extern struct trieNode * inHosts(struct trieNode *root, char *domain_name);
extern void *GetHostsEntry(struct trieNode *p, char type);
extern struct trieNode *InitHosts(FILE *hosts);
extern void InsertHosts(struct trieNode *root, char *domain_name, uint32_t *ip4, __uint128_t *ip6);