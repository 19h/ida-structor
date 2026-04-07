#include <stdint.h>
#include <stdio.h>

static volatile uint64_t sink;

struct WindowedFrame {
    uint32_t magic;       // 0x00
    uint16_t state;       // 0x04
    uint16_t pad;         // 0x06
    uint64_t ident;       // 0x08
    uint32_t values[3];   // 0x10
    uint8_t tail;         // 0x1C
};

__attribute__((noinline))
void init_frame(struct WindowedFrame *f) {
    f->magic = 0xABCD1234U;
    f->state = 0x55AAU;
    f->ident = 0x1122334455667788ULL;
    f->values[0] = 11;
    f->values[1] = 22;
    f->values[2] = 33;
    f->tail = 0x7F;
}

__attribute__((noinline))
void consume_window(void *mid) {
    uint8_t *p = (uint8_t *)mid;
    sink ^= *(uint32_t *)(p - 0x10);
    sink ^= *(uint16_t *)(p - 0x0C);
    sink ^= *(uint64_t *)(p - 0x08);
    sink ^= *(uint32_t *)(p + 0x00);
    sink ^= *(uint32_t *)(p + 0x04);
    sink ^= *(uint32_t *)(p + 0x08);
    sink ^= *(uint8_t *)(p + 0x0C);
}

int main(void) {
    struct WindowedFrame frame;

    init_frame(&frame);
    consume_window((uint8_t *)&frame + 0x10);

    printf("sink=%llx\n", (unsigned long long)sink);
    return 0;
}
