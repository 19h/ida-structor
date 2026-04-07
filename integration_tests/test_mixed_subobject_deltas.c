#include <stdint.h>
#include <stdio.h>

static volatile uint64_t sink;

struct ChildDelta {
    uint32_t kind;
    uint32_t flags;
    uint64_t value;
};

struct ParentDelta {
    uint32_t head;
    struct ChildDelta left;
    uint32_t mid;
    struct ChildDelta right;
    uint64_t tail;
};

__attribute__((noinline))
void init_deltas(struct ParentDelta *p) {
    p->head = 1;
    p->left.kind = 10;
    p->left.flags = 11;
    p->left.value = 0x1111111122222222ULL;
    p->mid = 2;
    p->right.kind = 20;
    p->right.flags = 21;
    p->right.value = 0x3333333344444444ULL;
    p->tail = 0x5555666677778888ULL;
}

__attribute__((noinline))
void read_child(void *child) {
    uint8_t *b = (uint8_t *)child;
    sink ^= *(uint32_t *)(b + 0x00);
    sink ^= *(uint32_t *)(b + 0x04);
    sink ^= *(uint64_t *)(b + 0x08);
}

__attribute__((noinline))
void read_mixed_anchor(void *anchor) {
    uint8_t *b = (uint8_t *)anchor;
    sink ^= *(uint32_t *)(b - 0x10);
    read_child(b - 0x0C);
    sink ^= *(uint32_t *)(b + 0x00);
    read_child(b + 0x04);
    sink ^= *(uint64_t *)(b + 0x14);
}

int main(void) {
    struct ParentDelta p;
    init_deltas(&p);
    read_mixed_anchor((uint8_t *)&p + 0x14);
    printf("sink=%llx\n", (unsigned long long)sink);
    return 0;
}
