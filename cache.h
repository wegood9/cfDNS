#include <stdio.h>
#include <stdint.h>
#include <time.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>
#include <stdlib.h>
#include <sys/queue.h>

#include "hash.h"
#include "uthash/uthash.h"

extern pthread_mutex_t cache_lock;

struct dns_cache
{
    uint32_t ip4; //网络序
    uint32_t ttl; //主机序
    time_t expire_time;
    __uint128_t ip6;
};

typedef struct LRUCache {
    int key;
    struct dns_cache value;
    int capacity;
    struct LRUCache *next;
    struct LRUCache *prev;
    UT_hash_handle hh; /* makes this structure hashable */
} LRUCache;



struct list_head
{
	struct list_head *next, *prev;
};

extern LRUCache *InitCache();
extern void AddEntryToCache(uint32_t name_hash, uint32_t ttl, uint32_t *ip4, __uint128_t *ip6);
extern struct dns_cache *GetCacheEntry(uint32_t name_hash);