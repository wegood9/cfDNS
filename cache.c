#include "config.h"
#include "debug.h"
#include "uthash/uthash.h"

pthread_mutex_t cache_lock;

LRUCache *uthash = NULL;

LRUCache *InitCache() {
    return lRUCacheCreate(raw_config.cache_size);
}

void AddEntryToCache(uint32_t name_hash, uint32_t ttl, uint32_t *ip4, __uint128_t *ip6) {
    struct dns_cache new_entry;
    LOG(LOG_DBG, "Add new cache entry for %u\n", name_hash);
    new_entry.ttl = ttl;
    new_entry.expire_time = time(NULL) + ttl;
    if (ip4)
        new_entry.ip4 = *ip4;
    else if (ip6)
        new_entry.ip6 = *ip6;
    lRUCachePut(cache, name_hash, new_entry);
}

//查询并提前该域名
struct dns_cache *GetCacheEntry(uint32_t name_hash) {
    struct dns_cache* tmp = lRUCacheGet(cache, name_hash);
    if (!tmp)
        LOG(LOG_DBG, "Cache missed: %d\n", name_hash);
    else if (tmp->expire_time < time(NULL))
        LOG(LOG_DBG, "Cache expired: %d\n", name_hash);
    else
        return tmp;
    return NULL;
}

/* 链表中添加一个节点(到链表头的位置) */
void ListAdd(LRUCache *head, LRUCache *lt) {
    lt->next = head->next;
    lt->prev = head;
    head->next->prev = lt;
    head->next = lt;
}

/* 链表中删除一个节点 */
void ListDel(LRUCache *lt) {
    lt->prev->next = lt->next;
    lt->next->prev = lt->prev;
}

LRUCache* lRUCacheCreate(int capacity) {    
    // 链表头申请一个空间，用于后续的链表管理
    LRUCache *listHead = (LRUCache*)malloc(sizeof(LRUCache));
    listHead->capacity = capacity;
    listHead->next = listHead;
    listHead->prev = listHead;
    return listHead;
}

static struct dns_cache *lRUCacheGet(LRUCache* obj, int key) {
    LRUCache *s;
    HASH_FIND_INT(uthash, &key, s);
    if (s == NULL) {
        return NULL;
    } else {
        // 从链表中删除，再加到链表头
        ListDel(s);
        ListAdd(obj, s);
        return &(s->value);
    }
}

void lRUCachePut(LRUCache* obj, int key, struct dns_cache value) {
    LRUCache *s = NULL;
    HASH_FIND_INT(uthash, &key, s);
    if (s != NULL) { // found
        // 删除链表节点，并添加到链表头
        ListDel(s);
        ListAdd(obj, s);
        s->value = value; // 修改value
        return;
    }
    if (obj->capacity == HASH_COUNT(uthash)) {  // hash桶满的情况            
            s = obj->prev; // s指向链表的尾部            
            HASH_DEL(uthash, s); // 删除尾部元素在hash中的位置 
            ListDel(s); // 链表中删除
            free(s);
    }    
    s = (LRUCache *)malloc(sizeof(LRUCache));
    s->key = key;
    s->value = value;
    HASH_ADD_INT(uthash, key, s);
    ListAdd(obj, s);   //添加到链表头
}

void lRUCacheFree(LRUCache* obj) {
    LRUCache *s, *tmp;
    HASH_ITER(hh, uthash, s, tmp) {
        HASH_DEL(uthash, s);
        free(s);
    }
    free(obj);
    uthash = NULL;
}