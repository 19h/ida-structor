#include <stdint.h>
#include <stdio.h>

static volatile uint64_t sink;

struct __attribute__((packed)) PackedRecord {
    uint8_t kind;         // 0x00
    uint16_t flags;       // 0x01
    uint32_t count;       // 0x03
    uint8_t small[3];     // 0x07
    uint64_t cookie;      // 0x0A
    uint16_t tail;        // 0x12
};

__attribute__((noinline))
void init_packed(void *p) {
    uint8_t *b = (uint8_t *)p;
    *(uint8_t *)(b + 0x00) = 7;
    *(uint16_t *)(b + 0x01) = 0x35;
    *(uint32_t *)(b + 0x03) = 0x11223344U;
    b[0x07] = 0x10;
    b[0x08] = 0x20;
    b[0x09] = 0x30;
    *(uint64_t *)(b + 0x0A) = 0xCAFEBABE11223344ULL;
    *(uint16_t *)(b + 0x12) = 0x7788;
}

__attribute__((noinline))
void read_packed(void *p) {
    uint8_t *b = (uint8_t *)p;
    sink ^= *(uint8_t *)(b + 0x00);
    sink ^= *(uint16_t *)(b + 0x01);
    sink ^= *(uint32_t *)(b + 0x03);
    sink ^= *(uint64_t *)(b + 0x0A);
    sink ^= *(uint16_t *)(b + 0x12);
}

__attribute__((noinline))
void read_small_array(void *p) {
    uint8_t *b = (uint8_t *)p;
    sink ^= b[0x07];
    sink ^= b[0x08];
    sink ^= b[0x09];
}

__attribute__((noinline))
void inspect_flag_slices(void *p) {
    uint8_t *b = (uint8_t *)p;
    uint16_t flags = *(uint16_t *)(b + 0x01);
    sink ^= (flags & 0x3);
    sink ^= ((flags >> 2) & 0x7);
}

int main(void) {
    struct PackedRecord rec;

    init_packed(&rec);
    read_packed(&rec);
    read_small_array(&rec);
    inspect_flag_slices(&rec);

    printf("sink=%llx\n", (unsigned long long)sink);
    return 0;
}
