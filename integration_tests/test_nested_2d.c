#include <stdint.h>
#include <stdio.h>

static volatile uint64_t sink;

struct MatrixWrap {
    uint32_t rows;
    uint32_t cols;
    uint16_t grid[2][3];
    uint8_t marks[2][2];
    uint32_t tail;
};

__attribute__((noinline))
void init_matrix(void *p) {
    uint8_t *b = (uint8_t *)p;
    *(uint32_t *)(b + 0x00) = 2;
    *(uint32_t *)(b + 0x04) = 3;
    *(uint16_t *)(b + 0x08) = 11;
    *(uint16_t *)(b + 0x0A) = 12;
    *(uint16_t *)(b + 0x0C) = 13;
    *(uint16_t *)(b + 0x0E) = 21;
    *(uint16_t *)(b + 0x10) = 22;
    *(uint16_t *)(b + 0x12) = 23;
    b[0x14] = 1;
    b[0x15] = 2;
    b[0x16] = 3;
    b[0x17] = 4;
    *(uint32_t *)(b + 0x18) = 0xABCD1234U;
}

__attribute__((noinline))
void read_matrix(void *p) {
    uint8_t *b = (uint8_t *)p;
    sink ^= *(uint32_t *)(b + 0x00);
    sink ^= *(uint32_t *)(b + 0x04);
    sink ^= *(uint16_t *)(b + 0x08);
    sink ^= *(uint16_t *)(b + 0x0A);
    sink ^= *(uint16_t *)(b + 0x0C);
    sink ^= *(uint16_t *)(b + 0x0E);
    sink ^= *(uint16_t *)(b + 0x10);
    sink ^= *(uint16_t *)(b + 0x12);
    sink ^= *(uint32_t *)(b + 0x18);
}

__attribute__((noinline))
void read_marks(void *p) {
    uint8_t *b = (uint8_t *)p;
    sink ^= b[0x14];
    sink ^= b[0x15];
    sink ^= b[0x16];
    sink ^= b[0x17];
}

int main(void) {
    struct MatrixWrap m;
    init_matrix(&m);
    read_matrix(&m);
    read_marks(&m);
    printf("sink=%llx\n", (unsigned long long)sink);
    return 0;
}
