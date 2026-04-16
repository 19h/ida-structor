#include <stdint.h>
#include <stdio.h>

static volatile uint64_t sink;

struct AliasLifetime {
    uint32_t kind;
    uint32_t tag;
    uint64_t value;
    uint16_t state;
};

struct AliasOther {
    uint8_t pad[0x20];
    uint32_t poison;
    uint64_t bogus;
};

__attribute__((noinline))
void init_alias_lifetime(void *p) {
    uint8_t *b = (uint8_t *)p;
    *(uint32_t *)(b + 0x00) = 0x44;
    *(uint64_t *)(b + 0x08) = 0x123456789ABCDEF0ULL;
    *(uint16_t *)(b + 0x10) = 0x77;
}

__attribute__((noinline))
void init_alias_other(void *p) {
    uint8_t *b = (uint8_t *)p;
    *(uint32_t *)(b + 0x20) = 0xAA55AA55U;
    *(uint64_t *)(b + 0x28) = 0x0BADF00D0D15EA5EULL;
}

__attribute__((noinline))
void alias_rebind_read(void *p) {
    void *tmp = p;
    sink ^= *(uint32_t *)tmp;
    tmp = (uint8_t *)tmp + 0x08;
    sink ^= *(uint64_t *)tmp;
    sink ^= *(uint16_t *)((uint8_t *)tmp + 0x08);
}

__attribute__((noinline))
void alias_overwrite_read(void *p, void *other) {
    void *tmp = p;
    sink ^= *(uint32_t *)tmp;
    sink ^= *(uint64_t *)((uint8_t *)tmp + 0x08);
    tmp = other;
    sink ^= *(uint32_t *)((uint8_t *)tmp + 0x20);
    sink ^= *(uint64_t *)((uint8_t *)tmp + 0x28);
    sink ^= *(uint16_t *)((uint8_t *)p + 0x10);
}

int main(void) {
    struct AliasLifetime primary;
    struct AliasOther other;

    init_alias_lifetime(&primary);
    init_alias_other(&other);
    alias_rebind_read(&primary);
    alias_overwrite_read(&primary, &other);

    printf("sink=%llx\n", (unsigned long long)sink);
    return 0;
}
