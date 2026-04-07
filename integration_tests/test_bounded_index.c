#include <stdint.h>
#include <stdio.h>

static volatile uint64_t sink;

struct IndexedArray {
    uint32_t count;
    uint32_t values[4];
    uint16_t marks[2];
};

__attribute__((noinline))
void init_indexed(struct IndexedArray *p) {
    p->count = 4;
    p->values[0] = 10;
    p->values[1] = 20;
    p->values[2] = 30;
    p->values[3] = 40;
    p->marks[0] = 1;
    p->marks[1] = 2;
}

__attribute__((noinline))
void read_indexed(void *p, int idx) {
    uint8_t *b = (uint8_t *)p;
    if ((unsigned)idx < 4) {
        sink ^= *(uint32_t *)(b + 0x04 + idx * 4);
    }
}

__attribute__((noinline))
void read_marks(void *p) {
    uint8_t *b = (uint8_t *)p;
    sink ^= *(uint16_t *)(b + 0x14);
    sink ^= *(uint16_t *)(b + 0x16);
}

int main(void) {
    struct IndexedArray arr;
    init_indexed(&arr);
    read_indexed(&arr, 0);
    read_indexed(&arr, 2);
    read_marks(&arr);
    printf("sink=%llx\n", (unsigned long long)sink);
    return 0;
}
