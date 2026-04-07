#include <stdint.h>
#include <stdio.h>

static volatile uint64_t sink;

struct Entry {
    uint32_t tag;
    uint32_t flags;
    uint64_t value;
};

struct EntryTable {
    uint32_t count;       // 0x00
    uint32_t mode;        // 0x04
    struct Entry items[4]; // 0x08
    uint8_t checksum[4];  // 0x48
};

__attribute__((noinline))
void init_table(struct EntryTable *t) {
    t->count = 4;
    t->mode = 2;
    for (int i = 0; i < 4; ++i) {
        t->items[i].tag = (uint32_t)(0x100 + i);
        t->items[i].flags = (uint32_t)(0x200 + i);
        t->items[i].value = 0xAAAABBBB00000000ULL + (uint64_t)i;
        t->checksum[i] = (uint8_t)(0x10 + i);
    }
}

__attribute__((noinline))
void read_table(void *p) {
    uint8_t *b = (uint8_t *)p;
    sink ^= *(uint32_t *)(b + 0x00);
    sink ^= *(uint32_t *)(b + 0x04);
    sink ^= *(uint32_t *)(b + 0x08);
    sink ^= *(uint32_t *)(b + 0x18);
    sink ^= *(uint32_t *)(b + 0x28);
    sink ^= *(uint32_t *)(b + 0x38);
    sink ^= *(uint64_t *)(b + 0x10);
    sink ^= *(uint64_t *)(b + 0x20);
    sink ^= *(uint64_t *)(b + 0x30);
    sink ^= *(uint64_t *)(b + 0x40);
}

__attribute__((noinline))
void update_tag(void *p, int idx, uint32_t value) {
    uint8_t *b = (uint8_t *)p;
    *(uint32_t *)(b + 0x08 + idx * 16) = value;
}

__attribute__((noinline))
void read_checksum(void *p) {
    uint8_t *b = (uint8_t *)p;
    sink ^= b[0x48];
    sink ^= b[0x49];
    sink ^= b[0x4A];
    sink ^= b[0x4B];
}

int main(void) {
    struct EntryTable table;

    init_table(&table);
    read_table(&table);
    update_tag(&table, 2, 0xFEEDU);
    read_checksum(&table);

    printf("sink=%llx\n", (unsigned long long)sink);
    return 0;
}
