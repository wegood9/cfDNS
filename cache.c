#include "cache.h"
#include "config.h"
#include "debug.h"

pthread_mutex_t cache_lock;

struct dns_cache *InitCache() {
    struct dns_cache *head = malloc(sizeof(struct dns_cache));
    INIT_LIST_HEAD(&head->list);
    head->hash = 0; //当前缓存数量
    return head;
}


void AddEntryToCache(uint32_t name_hash, uint32_t ttl, uint32_t *ip4, __uint128_t *ip6) {
    struct dns_cache *new_entry = (struct dns_cache *)malloc(sizeof(struct dns_cache));
    struct dns_cache *trail_entry;
    LOG(LOG_DBG, "Add new cache entry for %u\n", name_hash);
    new_entry->hash = name_hash;
    new_entry->ttl = ttl;
    new_entry->expire_time = time(NULL) + ttl;
    if (ip4)
        new_entry->ip4 = *ip4;
    else if (ip6)
        new_entry->ip6 = *ip6;
    list_add(&new_entry->list, cache);
    cache->hash++; //容量加1
    while (cache->hash > raw_config.cache_size)
    {
        //LRU删去尾节点
        LOG(LOG_INFO, "Cache is FULL, deleting one entry\n");
        trail_entry = cache->list.prev;
        list_del(cache->list.prev);
        free(trail_entry);
        cache->hash--;
    }
    LOG(LOG_DBG, "Added cache entry: %u\n", name_hash);
}

//查询并提前该域名
struct dns_cache *GetCacheEntry(uint32_t name_hash) {
    struct list_head *pos = NULL, *n = NULL;
    struct dns_cache *cur;
    list_for_each_safe(pos, n, &cache->list) {
        cur = pos;

        if (cur->hash == name_hash) {
            if (cur->expire_time > time(NULL)) {
                //提前对应条目
                list_del(pos);
                list_add(pos,&cache->list);
                return cur;
            }
            else {
                LOG(LOG_DBG, "Deleted expired entry: %u\n", name_hash);
                list_del(pos);
                cache->hash--;
                free(cur);
                return NULL;
            }
        }
        //删去过期条目
        else if (cur->expire_time <= time(NULL)) {
            LOG(LOG_DBG, "Deleted expired entry: %u\n", name_hash);
            list_del(pos);
            cache->hash--;
            free(cur);
        }
    }

    return NULL;
}

void UpdateCacheEntry(struct dns_cache *entry, uint32_t name_hash, uint32_t ttl, uint32_t *ip4, __uint128_t *ip6) {
    if (entry && entry->hash == name_hash) {
        entry->ttl = ttl;
        entry->expire_time = time(NULL) + ttl;
        if (ip4)
            entry->ip4 = *ip4;
        else if (ip6)
            entry->ip6 = *ip6;
    }
}