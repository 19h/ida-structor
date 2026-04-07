#include <stdint.h>
#include <stdio.h>

static volatile uint64_t sink;

struct OverlapSource {
    uint64_t whole;
    uint32_t next;
};

__attribute__((noinline))
void init_overlap(struct OverlapSource *p) {
    p->whole = 0x1122334455667788ULL;
    p->next = 0xAABBCCDDU;
}

__attribute__((noinline))
void read_overlap(void *p) {
    uint8_t *b = (uint8_t *)p;
    sink ^= *(uint64_t *)(b + 0x00);
    sink ^= *(uint32_t *)(b + 0x00);
    sink ^= *(uint16_t *)(b + 0x02);
    sink ^= *(uint32_t *)(b + 0x08);
}

__attribute__((noinline))
void read_shifted_overlap(void *p) {
    uint8_t *b = (uint8_t *)p;
    sink ^= *(uint32_t *)(b + 0x02);
    sink ^= *(uint16_t *)(b + 0x04);
}

int main(void) {
    struct OverlapSource source;

    init_overlap(&source);
    read_overlap(&source);
    read_shifted_overlap(&source);

    printf("sink=%llx\n", (unsigned long long)sink);
    return 0;
}
