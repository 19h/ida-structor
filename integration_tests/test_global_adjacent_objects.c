#include <stdint.h>
#include <stdio.h>

static volatile uint64_t sink;
static uint8_t g_dual_arena[0x80];

#define LEFT_BASE   0x00
#define RIGHT_BASE  0x40

#define R_MAGIC     0x00
#define R_FLAGS     0x04
#define R_VALUE     0x08
#define R_LINK      0x10

__attribute__((noinline))
void record_ctor(void *dst, uint32_t magic, uint64_t value) {
    uint8_t *b = (uint8_t *)dst;
    *(uint32_t *)(b + R_MAGIC) = magic;
    *(uint32_t *)(b + R_FLAGS) = magic ^ 0x33U;
    *(uint64_t *)(b + R_VALUE) = value;
    *(void **)(b + R_LINK) = dst;
}

__attribute__((noinline))
void build_left(void) {
    record_ctor(g_dual_arena + LEFT_BASE, 0x1111U, 0xAAAABBBBCCCCDDDDULL);
}

__attribute__((noinline))
void build_right(void) {
    record_ctor(g_dual_arena + RIGHT_BASE, 0x2222U, 0x1111222233334444ULL);
}

__attribute__((noinline))
void use_left(void) {
    uint8_t *b = g_dual_arena + LEFT_BASE;
    sink ^= *(uint32_t *)(b + R_MAGIC);
    sink ^= *(uint32_t *)(b + R_FLAGS);
    sink ^= *(uint64_t *)(b + R_VALUE);
}

__attribute__((noinline))
void use_right(void) {
    uint8_t *b = g_dual_arena + RIGHT_BASE;
    sink ^= *(uint32_t *)(b + R_MAGIC);
    sink ^= *(uint32_t *)(b + R_FLAGS);
    sink ^= *(uint64_t *)(b + R_VALUE);
    sink ^= (uint64_t)(uintptr_t)*(void **)(b + R_LINK);
}

int main(void) {
    build_left();
    build_right();
    use_left();
    use_right();
    printf("sink=%llx\n", (unsigned long long)sink);
    return 0;
}
