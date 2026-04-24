#include <stdint.h>
#include <stdio.h>

static volatile uint64_t sink;

struct ChildObject {
    uint8_t pad0[0x80];
    uint32_t status;
    uint32_t count;
};

struct RootWithPointer {
    uint32_t magic;
    uint8_t pad0[0x34];
    struct ChildObject *child;
    uint32_t tail;
};

__attribute__((noinline))
void init_pointer_field_fixture(struct RootWithPointer *root, struct ChildObject *child) {
    root->magic = 0x12345678U;
    root->child = child;
    root->tail = 0xABCDEF01U;
    child->status = 0x44U;
    child->count = 0x55U;
}

__attribute__((noinline))
void use_pointer_field(void *p) {
    uint8_t *b = (uint8_t *)p;
    void *child = *(void **)(b + 0x38);

    sink ^= *(uint32_t *)(b + 0x00);
    sink ^= (uint64_t)(uintptr_t)child;
    sink ^= *(uint32_t *)(b + 0x40);

    sink ^= *(uint32_t *)((uint8_t *)child + 0x80);
    sink ^= *(uint32_t *)((uint8_t *)child + 0x84);
}

int main(void) {
    struct RootWithPointer root;
    struct ChildObject child;
    init_pointer_field_fixture(&root, &child);
    use_pointer_field(&root);
    printf("sink=%llx\n", (unsigned long long)sink);
    return 0;
}
