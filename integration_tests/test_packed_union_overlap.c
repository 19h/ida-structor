#include <stdint.h>
#include <stdio.h>

static volatile uint64_t sink;

struct __attribute__((packed)) PackedUnionView {
    uint8_t tag;
    uint32_t whole;
    uint16_t tail;
};

__attribute__((noinline))
void init_packed_union(void *p) {
    uint8_t *b = (uint8_t *)p;
    b[0x00] = 9;
    *(uint32_t *)(b + 0x01) = 0x11223344U;
    *(uint16_t *)(b + 0x05) = 0x5566U;
}

__attribute__((noinline))
void read_whole(void *p) {
    uint8_t *b = (uint8_t *)p;
    sink ^= *(uint8_t *)(b + 0x00);
    sink ^= *(uint32_t *)(b + 0x01);
    sink ^= *(uint16_t *)(b + 0x05);
}

__attribute__((noinline))
void read_parts(void *p) {
    uint8_t *b = (uint8_t *)p;
    sink ^= *(uint16_t *)(b + 0x01);
    sink ^= *(uint16_t *)(b + 0x03);
}

int main(void) {
    struct PackedUnionView view;
    init_packed_union(&view);
    read_whole(&view);
    read_parts(&view);
    printf("sink=%llx\n", (unsigned long long)sink);
    return 0;
}
