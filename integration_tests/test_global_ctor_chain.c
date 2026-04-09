#include <stdint.h>
#include <stdio.h>

static volatile uint64_t sink;
static uint8_t g_widget[0x40];

#define W_MAGIC 0x00
#define W_FLAGS 0x04
#define W_VALUE 0x08
#define W_SELF  0x10
#define W_COUNT 0x18
#define W_TAG0  0x20
#define W_TAG1  0x21
#define W_TAG2  0x22
#define W_TAG3  0x23

__attribute__((noinline))
void widget_ctor(void *dst, uint32_t seed) {
    uint8_t *b = (uint8_t *)dst;
    *(uint32_t *)(b + W_MAGIC) = 0xABCD0000U | seed;
    *(uint32_t *)(b + W_FLAGS) = seed * 3U;
    *(uint64_t *)(b + W_VALUE) = 0x1111111100000000ULL | seed;
    *(void **)(b + W_SELF) = dst;
    *(uint32_t *)(b + W_COUNT) = seed + 5U;
    b[W_TAG0] = 'W';
    b[W_TAG1] = 'I';
    b[W_TAG2] = 'D';
    b[W_TAG3] = (uint8_t)('0' + seed);
}

__attribute__((noinline))
void widget_ctor_stage3(void *dst) {
    widget_ctor(dst, 7U);
}

__attribute__((noinline))
void widget_ctor_stage2(void *dst) {
    widget_ctor_stage3(dst);
}

__attribute__((noinline))
void widget_ctor_stage1(void) {
    void *slot = g_widget;
    widget_ctor_stage2(slot);
}

__attribute__((noinline))
void widget_use_leaf(void *dst) {
    uint8_t *b = (uint8_t *)dst;
    sink ^= *(uint32_t *)(b + W_FLAGS);
    sink ^= *(uint64_t *)(b + W_VALUE);
    sink ^= b[W_TAG2];
}

__attribute__((noinline))
void widget_use_global(void) {
    uint8_t *b = g_widget;
    sink ^= *(uint32_t *)(b + W_MAGIC);
    sink ^= *(uint32_t *)(b + W_COUNT);
    sink ^= (uint64_t)(uintptr_t)*(void **)(b + W_SELF);
    widget_use_leaf(b);
}

int main(void) {
    widget_ctor_stage1();
    widget_use_global();
    printf("sink=%llx\n", (unsigned long long)sink);
    return 0;
}
