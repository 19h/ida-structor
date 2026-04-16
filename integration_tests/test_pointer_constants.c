#include <stdint.h>
#include <stdio.h>

static volatile uint64_t sink;
static uint64_t cookie_a = 0x1111111111111111ULL;
static uint64_t cookie_b = 0x2222222222222222ULL;

typedef void (*handler_fn)(uint32_t value);

__attribute__((noinline))
static void handler_a(uint32_t value) {
    sink ^= (uint64_t)value + 0xA;
}

__attribute__((noinline))
static void handler_b(uint32_t value) {
    sink ^= (uint64_t)value + 0xB;
}

__attribute__((noinline))
void configure_and_invoke(void *p, int which, uint32_t value) {
    uint8_t *b = (uint8_t *)p;

    if (which) {
        *(handler_fn *)(b + 0x00) = handler_a;
        *(void **)(b + 0x08) = &cookie_a;
    } else {
        *(handler_fn *)(b + 0x00) = handler_b;
        *(void **)(b + 0x08) = &cookie_b;
    }

    (*(handler_fn *)(b + 0x00))(value);
    sink ^= **(uint64_t **)(b + 0x08);

    if (*(void **)(b + 0x08) == &cookie_a) {
        sink ^= 0x10;
    } else if (*(void **)(b + 0x08) == &cookie_b) {
        sink ^= 0x20;
    }
}

int main(void) {
    struct {
        handler_fn handler;
        void *cookie;
    } slot;

    configure_and_invoke(&slot, 0, 3);
    configure_and_invoke(&slot, 1, 7);

    printf("sink=%llx\n", (unsigned long long)sink);
    return 0;
}
