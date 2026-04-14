#include <stdint.h>
#include <stdio.h>

static volatile uint64_t sink;

#define ROOT_MAGIC   0x00
#define ROOT_CHILD   0x08
#define ROOT_TAIL0   0x30
#define ROOT_TAIL1   0x38

#define CHILD_MAGIC  0x00
#define CHILD_LEAF   0x08
#define CHILD_TAIL   0x20

#define LEAF_KIND    0x00
#define LEAF_FLAGS   0x04
#define LEAF_VALUE   0x08

__attribute__((noinline))
void leaf_init(void *leaf) {
    uint8_t *b = (uint8_t *)leaf;
    *(uint32_t *)(b + LEAF_KIND) = 3U;
    *(uint32_t *)(b + LEAF_FLAGS) = 7U;
    *(uint64_t *)(b + LEAF_VALUE) = 0x1111222233334444ULL;
}

__attribute__((noinline))
void child_init(void *child) {
    uint8_t *b = (uint8_t *)child;
    *(uint32_t *)(b + CHILD_MAGIC) = 0x4348494CU;
    leaf_init(b + CHILD_LEAF);
    *(uint64_t *)(b + CHILD_TAIL) = 0xAAAABBBBCCCCDDDDULL;
}

__attribute__((noinline))
void root_init(void *root) {
    uint8_t *b = (uint8_t *)root;
    *(uint32_t *)(b + ROOT_MAGIC) = 0x524F4F54U;
    child_init(b + ROOT_CHILD);
    *(uint64_t *)(b + ROOT_TAIL0) = 0x0123456789ABCDEFULL;
    *(uint32_t *)(b + ROOT_TAIL1) = 9U;
}

__attribute__((noinline))
void use_root(void *root) {
    uint8_t *b = (uint8_t *)root;
    sink ^= *(uint32_t *)(b + ROOT_MAGIC);
    sink ^= *(uint32_t *)(b + ROOT_CHILD + CHILD_MAGIC);
    sink ^= *(uint32_t *)(b + ROOT_CHILD + CHILD_LEAF + LEAF_KIND);
    sink ^= *(uint32_t *)(b + ROOT_CHILD + CHILD_LEAF + LEAF_FLAGS);
    sink ^= *(uint64_t *)(b + ROOT_CHILD + CHILD_LEAF + LEAF_VALUE);
    sink ^= *(uint64_t *)(b + ROOT_CHILD + CHILD_TAIL);
    sink ^= *(uint64_t *)(b + ROOT_TAIL0);
    sink ^= *(uint32_t *)(b + ROOT_TAIL1);
}

int main(void) {
    uint8_t root[0x40] = {0};
    root_init(root);
    use_root(root);
    printf("sink=%llx\n", (unsigned long long)sink);
    return 0;
}
