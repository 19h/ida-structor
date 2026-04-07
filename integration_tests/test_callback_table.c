#include <stdint.h>
#include <stdio.h>

static volatile uint64_t sink;

typedef void (*slot_cb_t)(uint64_t, uint32_t);

struct CallbackEntry {
    uint32_t id;
    uint32_t flags;
    slot_cb_t cb;
};

struct CallbackTable {
    uint32_t count;           // 0x00
    uint32_t mode;            // 0x04
    struct CallbackEntry entries[3]; // 0x08
    uint8_t states[3];        // 0x38
};

static void cb_a(uint64_t base, uint32_t value) { sink ^= base + value + 1; }
static void cb_b(uint64_t base, uint32_t value) { sink ^= base + value + 2; }
static void cb_c(uint64_t base, uint32_t value) { sink ^= base + value + 3; }

__attribute__((noinline))
void init_callback_table(void *p) {
    uint8_t *b = (uint8_t *)p;
    *(uint32_t *)(b + 0x00) = 3;
    *(uint32_t *)(b + 0x04) = 1;

    *(uint32_t *)(b + 0x08) = 10;
    *(uint32_t *)(b + 0x0C) = 0x11;
    *(slot_cb_t *)(b + 0x10) = cb_a;

    *(uint32_t *)(b + 0x18) = 20;
    *(uint32_t *)(b + 0x1C) = 0x22;
    *(slot_cb_t *)(b + 0x20) = cb_b;

    *(uint32_t *)(b + 0x28) = 30;
    *(uint32_t *)(b + 0x2C) = 0x44;
    *(slot_cb_t *)(b + 0x30) = cb_c;

    b[0x38] = 1;
    b[0x39] = 2;
    b[0x3A] = 3;
}

__attribute__((noinline))
void invoke_slot0(void *p) {
    uint8_t *b = (uint8_t *)p;
    slot_cb_t cb = *(slot_cb_t *)(b + 0x10);
    cb(*(uint32_t *)(b + 0x08), *(uint32_t *)(b + 0x0C));
}

__attribute__((noinline))
void invoke_slot2(void *p) {
    uint8_t *b = (uint8_t *)p;
    slot_cb_t cb = *(slot_cb_t *)(b + 0x30);
    cb(*(uint32_t *)(b + 0x28), *(uint32_t *)(b + 0x2C));
}

__attribute__((noinline))
void read_states(void *p) {
    uint8_t *b = (uint8_t *)p;
    sink ^= b[0x38];
    sink ^= b[0x39];
    sink ^= b[0x3A];
}

int main(void) {
    struct CallbackTable table;

    init_callback_table(&table);
    invoke_slot0(&table);
    invoke_slot2(&table);
    read_states(&table);

    printf("sink=%llx\n", (unsigned long long)sink);
    return 0;
}
