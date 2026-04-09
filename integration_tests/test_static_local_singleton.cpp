#include <cstdint>
#include <cstdio>

static volatile uint64_t sink;

class LocalCache {
public:
    uint32_t magic;
    uint32_t state;
    uint64_t total;
    void *self;

    explicit LocalCache(uint32_t seed)
        : magic(0x4C434348U + seed),
          state(seed + 1U),
          total(0xABC0000000000000ULL | seed),
          self(this) {}

    __attribute__((noinline)) void touch(uint32_t delta) {
        state ^= delta;
        total += delta;
    }
};

__attribute__((noinline))
static LocalCache *get_local_cache(void) {
    static LocalCache cache(7U);
    return &cache;
}

__attribute__((noinline))
void warm_local_cache(void) {
    LocalCache *cache = get_local_cache();
    cache->touch(3U);
    sink ^= cache->magic;
}

__attribute__((noinline))
void read_local_cache(void) {
    LocalCache *cache = get_local_cache();
    sink ^= cache->state;
    sink ^= cache->total;
    sink ^= reinterpret_cast<uintptr_t>(cache->self);
}

int main() {
    warm_local_cache();
    read_local_cache();
    std::printf("sink=%llx\n", static_cast<unsigned long long>(sink));
    return 0;
}
