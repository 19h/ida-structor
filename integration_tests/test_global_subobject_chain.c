#include <stdint.h>
#include <stdio.h>

static volatile uint64_t sink;
static uint8_t g_manager[0x80];

#define M_MAGIC      0x00
#define M_FLAGS      0x04
#define M_CHILD      0x20
#define M_TAIL       0x48

#define C_KIND       0x00
#define C_COUNT      0x04
#define C_VALUE      0x08
#define C_BACKPTR    0x10

__attribute__((noinline))
void child_ctor(void *child, uint32_t kind) {
    uint8_t *b = (uint8_t *)child;
    *(uint32_t *)(b + C_KIND) = kind;
    *(uint32_t *)(b + C_COUNT) = kind + 2U;
    *(uint64_t *)(b + C_VALUE) = 0x9000000000000000ULL | kind;
    *(void **)(b + C_BACKPTR) = child;
}

__attribute__((noinline))
void manager_ctor(void *dst) {
    uint8_t *b = (uint8_t *)dst;
    *(uint32_t *)(b + M_MAGIC) = 0x4D414E47U;
    *(uint32_t *)(b + M_FLAGS) = 0x55U;
    child_ctor(b + M_CHILD, 9U);
    *(uint64_t *)(b + M_TAIL) = 0xFEEDFACECAFEBEEFULL;
}

__attribute__((noinline))
void install_manager(void) {
    manager_ctor(g_manager);
}

__attribute__((noinline))
void use_child(void *child) {
    uint8_t *b = (uint8_t *)child;
    sink ^= *(uint32_t *)(b + C_KIND);
    sink ^= *(uint32_t *)(b + C_COUNT);
    sink ^= *(uint64_t *)(b + C_VALUE);
    sink ^= (uint64_t)(uintptr_t)*(void **)(b + C_BACKPTR);
}

__attribute__((noinline))
void use_manager(void) {
    uint8_t *b = g_manager;
    sink ^= *(uint32_t *)(b + M_MAGIC);
    sink ^= *(uint32_t *)(b + M_FLAGS);
    sink ^= *(uint64_t *)(b + M_TAIL);
    use_child(b + M_CHILD);
}

int main(void) {
    install_manager();
    use_manager();
    printf("sink=%llx\n", (unsigned long long)sink);
    return 0;
}
