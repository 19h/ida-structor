#include <stdint.h>
#include <stdio.h>

static volatile uint64_t sink;

struct ChildView {
    uint32_t kind;
    uint32_t flags;
    uint64_t value;
    uint8_t code[4];
};

struct ParentView {
    uint32_t magic;           // 0x00
    uint32_t count;           // 0x04
    struct ChildView left;    // 0x08
    struct ChildView right;   // 0x20
    uint64_t tail;            // 0x38
};

__attribute__((noinline))
void init_parent(struct ParentView *p) {
    p->magic = 0xABCD1234U;
    p->count = 2;

    p->left.kind = 1;
    p->left.flags = 0x10;
    p->left.value = 0x1111111122222222ULL;
    p->left.code[0] = 1;
    p->left.code[1] = 2;
    p->left.code[2] = 3;
    p->left.code[3] = 4;

    p->right.kind = 2;
    p->right.flags = 0x20;
    p->right.value = 0x3333333344444444ULL;
    p->right.code[0] = 5;
    p->right.code[1] = 6;
    p->right.code[2] = 7;
    p->right.code[3] = 8;

    p->tail = 0xFEEDFACECAFEBEEFULL;
}

__attribute__((noinline))
void consume_child(void *child) {
    uint8_t *b = (uint8_t *)child;
    sink ^= *(uint32_t *)(b + 0x00);
    sink ^= *(uint32_t *)(b + 0x04);
    sink ^= *(uint64_t *)(b + 0x08);
    sink ^= b[0x10];
    sink ^= b[0x11];
    sink ^= b[0x12];
    sink ^= b[0x13];
}

__attribute__((noinline))
void process_parent(void *p) {
    uint8_t *b = (uint8_t *)p;
    sink ^= *(uint32_t *)(b + 0x00);
    sink ^= *(uint32_t *)(b + 0x04);
    consume_child(b + 0x08);
    consume_child(b + 0x20);
    sink ^= *(uint64_t *)(b + 0x38);
}

int main(void) {
    struct ParentView parent;

    init_parent(&parent);
    process_parent(&parent);

    printf("sink=%llx\n", (unsigned long long)sink);
    return 0;
}
