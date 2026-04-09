#include <stdint.h>
#include <stdio.h>

static volatile uint64_t sink;
static uint8_t g_device[0x60];

#define D_MAGIC   0x00
#define D_FLAGS   0x04
#define D_BASE    0x08
#define D_LIMIT   0x10
#define D_COOKIE  0x18
#define D_STATE   0x20
#define D_SLOT0   0x28
#define D_SLOT1   0x30

__attribute__((noinline))
void device_header_ctor(void *dst) {
    uint8_t *b = (uint8_t *)dst;
    *(uint32_t *)(b + D_MAGIC) = 0x44564543U;
    *(uint32_t *)(b + D_FLAGS) = 0x14U;
    *(uint64_t *)(b + D_BASE) = 0x2000ULL;
    *(uint64_t *)(b + D_LIMIT) = 0x2080ULL;
}

__attribute__((noinline))
void device_attach_cookie(void *dst) {
    uint8_t *b = (uint8_t *)dst;
    *(void **)(b + D_COOKIE) = dst;
    *(uint32_t *)(b + D_STATE) = 0x31U;
}

__attribute__((noinline))
void device_publish_slots(void *dst) {
    uint8_t *b = (uint8_t *)dst;
    *(uint64_t *)(b + D_SLOT0) = 0xAAAABBBBCCCCDDDDULL;
    *(uint64_t *)(b + D_SLOT1) = 0x1111222233334444ULL;
}

__attribute__((noinline))
void bootstrap_device(void) {
    device_header_ctor(g_device);
}

__attribute__((noinline))
void finalize_device(void) {
    void *slot = g_device;
    device_attach_cookie(slot);
    device_publish_slots(slot);
}

__attribute__((noinline))
void use_device(void) {
    uint8_t *b = g_device;
    sink ^= *(uint32_t *)(b + D_MAGIC);
    sink ^= *(uint32_t *)(b + D_FLAGS);
    sink ^= *(uint64_t *)(b + D_BASE);
    sink ^= *(uint64_t *)(b + D_LIMIT);
    sink ^= (uint64_t)(uintptr_t)*(void **)(b + D_COOKIE);
    sink ^= *(uint32_t *)(b + D_STATE);
    sink ^= *(uint64_t *)(b + D_SLOT1);
}

int main(void) {
    bootstrap_device();
    finalize_device();
    use_device();
    printf("sink=%llx\n", (unsigned long long)sink);
    return 0;
}
