#include <stdint.h>
#include <stdio.h>

static volatile uint64_t sink;
static uint8_t g_state_storage[0x48];
static void *g_state_ptr;

#define P_MAGIC   0x00
#define P_FLAGS   0x04
#define P_VALUE   0x08
#define P_SELF    0x10
#define P_LIMIT   0x18
#define P_CODE    0x20

__attribute__((noinline))
void *alloc_state_storage(void) {
    return g_state_storage;
}

__attribute__((noinline))
void state_ctor(void *dst, uint32_t seed) {
    uint8_t *b = (uint8_t *)dst;
    *(uint32_t *)(b + P_MAGIC) = 0x53544154U;
    *(uint32_t *)(b + P_FLAGS) = seed ^ 0x22U;
    *(uint64_t *)(b + P_VALUE) = 0x1010101010101000ULL | seed;
    *(void **)(b + P_SELF) = dst;
    *(uint64_t *)(b + P_LIMIT) = 0x80ULL + seed;
    *(uint32_t *)(b + P_CODE) = seed + 0x40U;
}

__attribute__((noinline))
void publish_state(void) {
    void *slot = alloc_state_storage();
    g_state_ptr = slot;
    state_ctor(slot, 11U);
}

__attribute__((noinline))
void use_state_leaf(void *dst) {
    uint8_t *b = (uint8_t *)dst;
    sink ^= *(uint64_t *)(b + P_VALUE);
    sink ^= *(uint64_t *)(b + P_LIMIT);
}

__attribute__((noinline))
void use_state(void) {
    uint8_t *b = (uint8_t *)g_state_ptr;
    sink ^= *(uint32_t *)(b + P_MAGIC);
    sink ^= *(uint32_t *)(b + P_FLAGS);
    sink ^= (uint64_t)(uintptr_t)*(void **)(b + P_SELF);
    sink ^= *(uint32_t *)(b + P_CODE);
    use_state_leaf(b);
}

int main(void) {
    publish_state();
    use_state();
    printf("sink=%llx\n", (unsigned long long)sink);
    return 0;
}
