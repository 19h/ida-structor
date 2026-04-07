#include <stdint.h>
#include <stdio.h>

static volatile uint64_t sink;

struct AliasRecord {
    uint32_t kind;
    uint64_t ptr;
    uint16_t flags;
    uint8_t tail[3];
};

__attribute__((noinline))
void init_alias_record(void *p) {
    uint8_t *b = (uint8_t *)p;
    *(uint32_t *)(b + 0x00) = 0x44;
    *(uint64_t *)(b + 0x08) = 0x123456789ABCDEF0ULL;
    *(uint16_t *)(b + 0x10) = 0x77;
    b[0x12] = 1;
    b[0x13] = 2;
    b[0x14] = 3;
}

__attribute__((noinline))
void use_alias_read(void *p) {
    void *tmp = p;
    uint8_t *b = (uint8_t *)tmp;
    sink ^= *(uint32_t *)(b + 0x00);
    sink ^= *(uint64_t *)(b + 0x08);
    sink ^= *(uint16_t *)(b + 0x10);
}

__attribute__((noinline))
void use_alias_chain(void *p) {
    void *a = p;
    void *b0 = a;
    uint8_t *b = (uint8_t *)b0;
    sink ^= b[0x12];
    sink ^= b[0x13];
    sink ^= b[0x14];
}

int main(void) {
    struct AliasRecord rec;
    init_alias_record(&rec);
    use_alias_read(&rec);
    use_alias_chain(&rec);
    printf("sink=%llx\n", (unsigned long long)sink);
    return 0;
}
