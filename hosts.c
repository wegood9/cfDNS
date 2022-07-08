#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

#include "hosts.h"
#include "debug.h"
#include "config.h"

//只考虑传统域名
int GetIndex(char c) {
    if (c == '.')
        return 36;
        //第36号为.
    else if (c <= '9')
        return c - '0';
        //第0-9号为数字
    else if (c >= 'a')
        return c - 'a' + 10;
        //第10-35号为小写字母
    else
        return c - 'A' + 10;
        //不区分大小写
}

struct trieNode *NewTrieNode(void) {
    struct trieNode *newNode = malloc(sizeof(struct trieNode));
    if (!newNode) {
        LOG(LOG_FATAL, "Failed to allocate memory for hosts\n");
        exit(-1);
    }

    memset(newNode, 0, sizeof(struct trieNode));
    return newNode;
}

void InsertTrie(struct trieNode *root, char *domain_name, uint32_t *ip4, __uint128_t *ip6) {
    int len = strlen(domain_name), index;
    struct trieNode *p = root;

    for (int level = 0; level<len; level++)
    {
        index = GetIndex(domain_name[level]);
  
        //新节点
        if (!p->child[index])
            p->child[index] = NewTrieNode();
  
        p = p->child[index];
    }

    //叶子节点
    p->isLeaf = true;
    if (ip4)
        p->ip4 = *ip4;
    if (ip6)
        p->ip6 = *ip6;
}

void *LookupTrie(struct trieNode *root, char *domain_name, uint32_t *ip4, __uint128_t *ip6) {
    struct trieNode *p = root;
    int len = strlen(domain_name), index;

    for (int level = 0; level<len; level++) {
        index = GetIndex(domain_name[level]);
        if ((p->child[index]) == NULL)
            return NULL;
        p = p->child[index];
    }

    //根据指针确定查询的类型
    if (p != NULL && p->isLeaf) {
        if (ip4)
            *ip4 = p->ip4;
        else if (ip6)
            *ip6 = p->ip6;
        return p;
    }
  
    return NULL;
}

struct trieNode *InitHosts(FILE *hosts) {
    if (!hosts)
        return NULL;

    struct trieNode *root = NewTrieNode();
    struct sockaddr_in6 addr6;
    struct sockaddr_in addr4;
    char readin[256];
    char *token;

    while(fgets(readin,256,hosts)){
        if (readin[0] == '#' || readin[0] == '\n')
            continue;

        if (readin[strlen(readin) - 1] == '\n')
            readin[strlen(readin) - 1] = 0; //去掉换行符

        token = strtok(readin, " ");
        if (isValidIPv6(token)) {
            inet_pton(AF_INET6, token, &addr6.sin6_addr);
            token = strtok(NULL, " ");
            InsertTrie(root, token, NULL, &addr6.sin6_addr);
        }
        else if (isValidIPv4(token)) {
            inet_pton(AF_INET, token, &addr4.sin_addr);
            token = strtok(NULL, " ");
            InsertTrie(root, token, &addr4.sin_addr, NULL);
        }
        else
            token = strtok(NULL, " ");
    }
    close(hosts);
    return root;
}

struct trieNode * inHosts(struct trieNode *root, char *domain_name) {
    return LookupTrie(root, domain_name, NULL, NULL);
}

void *GetHostsEntry(struct trieNode *p, char type) {
    switch (type) {
    case 'A':
        return &p->ip4;
        break;
    case 'B':
        return &p->ip6;
        break;
    default:
        return NULL;
        break;
    }
}