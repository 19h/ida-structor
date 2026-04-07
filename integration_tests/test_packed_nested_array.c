#include <stdint.h>
#include <stdio.h>

static volatile uint64_t sink;

struct __attribute__((packed)) PackedEntry {
    uint16_t code;
    uint32_t value;
    uint8_t state;
};

struct __attribute__((packed)) PackedBundle {
    uint8_t kind;                 // 0x00
    uint16_t flags;               // 0x01
    struct PackedEntry items[3];  // 0x03
    uint8_t tail[3];              // 0x18
};

__attribute__((noinline))
void init_bundle(void *p) {
    uint8_t *b = (uint8_t *)p;
    *(uint8_t *)(b + 0x00) = 7;
    *(uint16_t *)(b + 0x01) = 0x33;

    *(uint16_t *)(b + 0x03) = 100;
    *(uint32_t *)(b + 0x05) = 0x11111111U;
    *(uint8_t *)(b + 0x09) = 1;

    *(uint16_t *)(b + 0x0A) = 200;
    *(uint32_t *)(b + 0x0C) = 0x22222222U;
    *(uint8_t *)(b + 0x10) = 2;

    *(uint16_t *)(b + 0x11) = 300;
    *(uint32_t *)(b + 0x13) = 0x33333333U;
    *(uint8_t *)(b + 0x17) = 3;

    b[0x18] = 9;
    b[0x19] = 8;
    b[0x1A] = 7;
}

__attribute__((noinline))
void read_bundle(void *p) {
    uint8_t *b = (uint8_t *)p;
    sink ^= *(uint8_t *)(b + 0x00);
    sink ^= *(uint16_t *)(b + 0x01);
    sink ^= *(uint32_t *)(b + 0x05);
    sink ^= *(uint32_t *)(b + 0x0C);
    sink ^= *(uint32_t *)(b + 0x13);
}

__attribute__((noinline))
void read_tail(void *p) {
    uint8_t *b = (uint8_t *)p;
    sink ^= b[0x18];
    sink ^= b[0x19];
    sink ^= b[0x1A];
}

int main(void) {
    struct PackedBundle bundle;

    init_bundle(&bundle);
    read_bundle(&bundle);
    read_tail(&bundle);

    printf("sink=%llx\n", (unsigned long long)sink);
    return 0;
}
