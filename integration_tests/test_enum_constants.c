#include <stdint.h>
#include <stdio.h>

static volatile uint64_t sink;

enum ModeKind {
    MODE_IDLE = 1,
    MODE_RUN = 2,
    MODE_STOP = 3,
};

struct EnumState {
    uint32_t mode;
    uint32_t state;
    uint16_t flags;
    uint8_t tail;
};

__attribute__((noinline))
void init_enum_state(struct EnumState *p) {
    p->mode = MODE_RUN;
    p->state = 0x20;
    p->flags = 0x5;
    p->tail = 9;
}

__attribute__((noinline))
void inspect_mode(void *p) {
    uint8_t *b = (uint8_t *)p;
    uint32_t mode = *(uint32_t *)(b + 0x00);
    if (mode == MODE_IDLE) sink ^= 1;
    else if (mode == MODE_RUN) sink ^= 2;
    else if (mode == MODE_STOP) sink ^= 3;
}

__attribute__((noinline))
void inspect_state(void *p) {
    uint8_t *b = (uint8_t *)p;
    uint32_t state = *(uint32_t *)(b + 0x04);
    if (state == 0x10) sink ^= 0x10;
    if (state == 0x20) sink ^= 0x20;
    if (state == 0x40) sink ^= 0x40;
    sink ^= *(uint16_t *)(b + 0x08);
    sink ^= *(uint8_t *)(b + 0x0A);
}

int main(void) {
    struct EnumState st;
    init_enum_state(&st);
    inspect_mode(&st);
    inspect_state(&st);
    printf("sink=%llx\n", (unsigned long long)sink);
    return 0;
}
