#include <stdint.h>
#include <stdlib.h>

#define NOINLINE __attribute__((noinline))
#define HEADER(base) ((uintptr_t)*(volatile uint16_t *)(base) + \
                      *(volatile uint64_t *)((uint8_t *)(base) + 8))
#define FIELD(pointer) (*(volatile uint32_t *)((uint8_t *)(pointer) + 32))

NOINLINE uintptr_t native_observe_address(void *pointer) {
    uintptr_t value = (uintptr_t)pointer;
    __asm__ volatile("" : "+r"(value));
    return value;
}

NOINLINE uintptr_t native_alias_direct(void *base, void *other, uint32_t flag) {
    (void)other;
    (void)flag;
    void *temporary = base;
    return HEADER(base) + FIELD(temporary) + native_observe_address(temporary);
}

NOINLINE uintptr_t native_alias_sibling_negative(void *base, void *other, uint32_t flag) {
    uintptr_t result = HEADER(base);
    void *temporary = other;
    if (flag) {
        temporary = base;
    } else {
        result += FIELD(temporary);
    }
    return result + native_observe_address(temporary);
}

NOINLINE uintptr_t native_alias_incoming_positive(void *base, void *other, uint32_t flag) {
    uintptr_t result = HEADER(base);
    void *temporary = base;
    if (flag) {
        temporary = other;
    } else {
        result += FIELD(temporary);
    }
    return result + native_observe_address(temporary);
}

NOINLINE uintptr_t native_alias_join_positive(void *base, void *other, uint32_t flag) {
    uintptr_t result = HEADER(base);
    void *temporary;
    if (flag) temporary = base;
    else temporary = other;
    return result + FIELD(temporary) + native_observe_address(temporary);
}

NOINLINE uintptr_t native_alias_offset_join(void *base, void *other, uint32_t flag) {
    (void)other;
    uintptr_t result = HEADER(base);
    void *temporary;
    if (flag) temporary = (uint8_t *)base + 8;
    else temporary = (uint8_t *)base + 16;
    return result + FIELD(temporary) + native_observe_address(temporary);
}

NOINLINE uintptr_t native_alias_correlated_negative(void *base, void *other, uint32_t flag) {
    uintptr_t result = HEADER(base);
    void *temporary = other;
    if (flag) temporary = base;
    if (!flag) result += FIELD(temporary);
    return result + native_observe_address(temporary);
}

NOINLINE uintptr_t native_alias_condition_reset(void *base, void *other, uint32_t flag) {
    uintptr_t result = HEADER(base);
    void *temporary = other;
    if (flag) temporary = base;
    flag = 0;
    if (!flag) result += FIELD(temporary);
    return result + native_observe_address(temporary);
}

NOINLINE uintptr_t native_alias_return_negative(void *base, void *other, uint32_t flag) {
    uintptr_t result = HEADER(base);
    void *temporary = other;
    if (flag) {
        temporary = base;
        return result + native_observe_address(temporary);
    }
    return result + FIELD(temporary) + native_observe_address(temporary);
}

NOINLINE uintptr_t native_alias_loop_carried(void *base, void *other, uint32_t flag) {
    uintptr_t result = HEADER(base);
    void *temporary = other;
    while (flag) {
        result += FIELD(temporary);
        temporary = base;
        --flag;
    }
    return result + native_observe_address(temporary);
}

NOINLINE uintptr_t native_alias_loop_zero(void *base, void *other, uint32_t flag) {
    uintptr_t result = HEADER(base);
    void *temporary = base;
    while (flag) {
        temporary = other;
        --flag;
    }
    return result + FIELD(temporary) + native_observe_address(temporary);
}

NOINLINE uintptr_t native_alias_switch_negative(void *base, void *other, uint32_t flag) {
    uintptr_t result = HEADER(base);
    void *temporary = other;
    switch (flag) {
        case 1: temporary = base; break;
        case 0: result += FIELD(temporary); break;
        default: break;
    }
    return result + native_observe_address(temporary);
}

NOINLINE uintptr_t native_alias_switch_fallthrough(void *base, void *other, uint32_t flag) {
    uintptr_t result = HEADER(base);
    void *temporary = other;
    switch (flag) {
        case 1: temporary = base; __attribute__((fallthrough));
        case 0: result += FIELD(temporary); break;
        default: break;
    }
    return result + native_observe_address(temporary);
}

int main(int argc, char **argv) {
    (void)argv;
    void *base = calloc(1, 128);
    void *other = calloc(1, 128);
    if (!base || !other) { free(base); free(other); return 1; }
    uintptr_t result = native_alias_direct(base, other, (uint32_t)argc);
    result += native_alias_sibling_negative(base, other, (uint32_t)argc);
    result += native_alias_incoming_positive(base, other, (uint32_t)argc);
    result += native_alias_join_positive(base, other, (uint32_t)argc);
    result += native_alias_offset_join(base, other, (uint32_t)argc);
    result += native_alias_correlated_negative(base, other, (uint32_t)argc);
    result += native_alias_condition_reset(base, other, (uint32_t)argc);
    result += native_alias_return_negative(base, other, (uint32_t)argc);
    result += native_alias_loop_carried(base, other, (uint32_t)argc);
    result += native_alias_loop_zero(base, other, (uint32_t)argc);
    result += native_alias_switch_negative(base, other, (uint32_t)argc);
    result += native_alias_switch_fallthrough(base, other, (uint32_t)argc);
    free(base);
    free(other);
    return (int)(result & 1);
}
