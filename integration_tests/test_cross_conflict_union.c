#include <stdint.h>
#include <stdio.h>

static volatile uint64_t sink;

struct ConflictRoot {
    uint32_t tag;
    uint32_t kind;
    uint64_t payload;
    uint32_t tail;
};

__attribute__((noinline))
void init_conflict(struct ConflictRoot *p) {
    p->tag = 1;
    p->kind = 2;
    p->payload = 0x1122334455667788ULL;
    p->tail = 3;
}

__attribute__((noinline))
void read_payload_whole(void *p) {
    uint8_t *b = (uint8_t *)p;
    sink ^= *(uint64_t *)(b + 0x08);
}

__attribute__((noinline))
void read_payload_split(void *p) {
    uint8_t *b = (uint8_t *)p;
    sink ^= *(uint32_t *)(b + 0x08);
    sink ^= *(uint32_t *)(b + 0x0C);
}

__attribute__((noinline))
void process_conflict(void *p) {
    uint8_t *b = (uint8_t *)p;
    sink ^= *(uint32_t *)(b + 0x00);
    sink ^= *(uint32_t *)(b + 0x04);
    read_payload_whole(p);
    read_payload_split(p);
    sink ^= *(uint32_t *)(b + 0x10);
}

int main(void) {
    struct ConflictRoot root;
    init_conflict(&root);
    process_conflict(&root);
    printf("sink=%llx\n", (unsigned long long)sink);
    return 0;
}
