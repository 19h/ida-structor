#include <stdint.h>
#include <stdio.h>

static volatile uint64_t sink;

union NumberView {
    uint32_t as_u32;
    float as_f32;
};

struct HeaderWithFlags {
    uint32_t magic;         // 0x00
    uint32_t flags;         // 0x04
    union NumberView view;  // 0x08
    uint16_t mode;          // 0x0C
    uint16_t bits;          // 0x0E
    uint8_t bytes[4];       // 0x10
};

__attribute__((noinline))
void init_header(void *p) {
    uint8_t *b = (uint8_t *)p;
    *(uint32_t *)(b + 0x00) = 0xDEADBEEFU;
    *(uint32_t *)(b + 0x04) = 0x15U;
    *(uint32_t *)(b + 0x08) = 0x40490FDBU;
    *(uint16_t *)(b + 0x0C) = 2U;
    *(uint16_t *)(b + 0x0E) = 0x003DU;
    b[0x10] = 1;
    b[0x11] = 2;
    b[0x12] = 3;
    b[0x13] = 4;
}

__attribute__((noinline))
void inspect_header(void *p) {
    uint8_t *b = (uint8_t *)p;
    sink ^= *(uint32_t *)(b + 0x00);
    sink ^= *(uint32_t *)(b + 0x04);
    sink ^= *(uint32_t *)(b + 0x08);
    sink ^= *(uint16_t *)(b + 0x0C);
}

__attribute__((noinline))
void inspect_float_view(void *p) {
    uint8_t *b = (uint8_t *)p;
    float f = *(float *)(b + 0x08);
    sink ^= (uint64_t)(*(uint32_t *)&f);
}

__attribute__((noinline))
void inspect_bits(void *p) {
    uint8_t *b = (uint8_t *)p;
    uint16_t bits = *(uint16_t *)(b + 0x0E);
    sink ^= (bits & 0x3);
    sink ^= ((bits >> 2) & 0x7);
    sink ^= ((bits >> 5) & 0x1);
}

__attribute__((noinline))
void inspect_bytes(void *p) {
    uint8_t *b = (uint8_t *)p;
    sink ^= b[0x10];
    sink ^= b[0x11];
    sink ^= b[0x12];
    sink ^= b[0x13];
}

int main(void) {
    struct HeaderWithFlags hdr;

    init_header(&hdr);
    inspect_header(&hdr);
    inspect_float_view(&hdr);
    inspect_bits(&hdr);
    inspect_bytes(&hdr);

    printf("sink=%llx\n", (unsigned long long)sink);
    return 0;
}
