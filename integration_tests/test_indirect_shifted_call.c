#include <stdint.h>
#include <stdio.h>

static volatile uint64_t sink;

typedef void (*ops_cb_t)(uint64_t, uint32_t);

struct ChildOps {
    ops_cb_t cb;
    uint32_t id;
    uint32_t flags;
};

struct IndirectParent {
    uint32_t magic;
    uint32_t count;
    struct ChildOps left;
    struct ChildOps right;
    uint8_t tail[2];
};

static void cb_left(uint64_t base, uint32_t flags) { sink ^= base + flags + 5; }
static void cb_right(uint64_t base, uint32_t flags) { sink ^= base + flags + 9; }

__attribute__((noinline))
void init_indirect(struct IndirectParent *p) {
    p->magic = 0xAB;
    p->count = 2;
    p->left.cb = cb_left;
    p->left.id = 10;
    p->left.flags = 0x11;
    p->right.cb = cb_right;
    p->right.id = 20;
    p->right.flags = 0x22;
    p->tail[0] = 1;
    p->tail[1] = 2;
}

__attribute__((noinline))
void invoke_child(void *child) {
    uint8_t *b = (uint8_t *)child;
    ops_cb_t cb = *(ops_cb_t *)(b + 0x00);
    cb(*(uint32_t *)(b + 0x08), *(uint32_t *)(b + 0x0C));
}

__attribute__((noinline))
void dispatch_parent(void *p) {
    uint8_t *b = (uint8_t *)p;
    sink ^= *(uint32_t *)(b + 0x00);
    sink ^= *(uint32_t *)(b + 0x04);
    invoke_child(b + 0x08);
    invoke_child(b + 0x18);
    sink ^= b[0x28];
    sink ^= b[0x29];
}

int main(void) {
    struct IndirectParent p;
    init_indirect(&p);
    dispatch_parent(&p);
    printf("sink=%llx\n", (unsigned long long)sink);
    return 0;
}
