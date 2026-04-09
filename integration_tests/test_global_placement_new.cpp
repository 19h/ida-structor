#include <cstdint>
#include <cstdio>
#include <new>

static volatile uint64_t sink;

class Gadget {
public:
    uint32_t magic;
    uint32_t flags;
    uint64_t value;
    void *cookie;
    uint16_t mode;
    uint16_t state;

    Gadget(uint32_t seed, void *owner)
        : magic(0x47414447U + seed),
          flags(seed * 5U),
          value(0x7000000000000000ULL | seed),
          cookie(owner),
          mode(static_cast<uint16_t>(seed + 2U)),
          state(static_cast<uint16_t>(seed + 9U)) {}

    __attribute__((noinline)) void bump(uint32_t delta) {
        flags ^= delta;
        value += delta;
    }
};

alignas(Gadget) static unsigned char g_gadget_storage[sizeof(Gadget)];
static Gadget *g_gadget;

__attribute__((noinline))
static Gadget *construct_gadget(void *storage, uint32_t seed) {
    return new (storage) Gadget(seed, storage);
}

__attribute__((noinline))
static void construct_gadget_stage2(void *storage) {
    g_gadget = construct_gadget(storage, 9U);
}

__attribute__((noinline))
void construct_gadget_stage1(void) {
    construct_gadget_stage2(g_gadget_storage);
}

__attribute__((noinline))
void use_gadget(void) {
    Gadget *g = g_gadget;
    sink ^= g->magic;
    sink ^= g->flags;
    sink ^= g->value;
    sink ^= reinterpret_cast<uintptr_t>(g->cookie);
    sink ^= g->mode;
    sink ^= g->state;
    g->bump(4U);
    sink ^= g->flags;
}

int main() {
    construct_gadget_stage1();
    use_gadget();
    std::printf("sink=%llx\n", static_cast<unsigned long long>(sink));
    return 0;
}
