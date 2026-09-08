#include <stdint.h>

// Keep four real argument locals available for controlled live ctree probes.
// No synthetic local indices or changes to the cfunc's lvar table are needed.
__attribute__((noinline))
uintptr_t alias_ctree_carrier(uintptr_t base, uintptr_t other,
                             uintptr_t temporary, int32_t flag) {
    __asm__ volatile("" : "+r"(base), "+r"(other), "+r"(temporary), "+r"(flag));
    return base ^ other ^ temporary ^ (uint32_t)flag;
}

int main(void) {
    return (int)alias_ctree_carrier(0, 1, 2, 3);
}
