#include <stdint.h>

#define HASH_A_INITVAL 0x710fc012
#define HASH_AAAA_INITVAL 0x3915a8ec

extern uint32_t hashlittle(const void *key, unsigned long length, uint32_t initval);