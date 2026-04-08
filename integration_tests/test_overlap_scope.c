#include <stdint.h>
#include <stdio.h>

struct Pair {
    int64_t left;
    int64_t right;
};

static volatile int64_t sink;

__attribute__((noinline)) static void pin_pair_ptr(struct Pair **slot) {
    asm volatile("" : "+m"(*slot) : : "memory");
}

__attribute__((noinline)) static void pin_u64(uint64_t *slot) {
    asm volatile("" : "+m"(*slot) : : "memory");
}

__attribute__((noinline)) static void use_raw(uint64_t value) {
    sink += (int64_t)(value & 1);
}

__attribute__((noinline)) int64_t overlap_scope(struct Pair *p, int flag) {
    int64_t result = 0;

    if (flag) {
        struct Pair *typed = p;
        pin_pair_ptr(&typed);
        result += typed->left;
        result += typed->right;
    }

    {
        uint64_t raw = (uint64_t) p;
        pin_u64(&raw);
        use_raw(raw);
        result += 3;
    }

    return result;
}

int main(void) {
    struct Pair pair = {4, 7};
    printf("%lld %lld\n", (long long) overlap_scope(&pair, 1), (long long) overlap_scope(&pair, 0));
    return 0;
}
