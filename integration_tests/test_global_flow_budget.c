#include <stdint.h>

#define NOINLINE __attribute__((noinline))
#define LOAD32(base, offset) (*(volatile uint32_t *)((uint8_t *)(base) + (offset)))

/* Byte storage remains global; each root is passed unshifted to its consumer. */
static uint8_t g_flow_complete[64] __attribute__((aligned(8)));
static uint8_t g_flow_insufficient[64] __attribute__((aligned(8)));
static uint8_t g_flow_empty[64] __attribute__((aligned(8)));
static uint8_t unrelated_storage[64] __attribute__((aligned(8)));
static volatile uint32_t branch_flag;
static volatile uintptr_t result_sink;

NOINLINE uintptr_t global_flow_observe_pointer(void *pointer) {
    uintptr_t value = (uintptr_t)pointer;
    __asm__ volatile("" : "+r"(value));
    return value;
}

NOINLINE uintptr_t global_flow_complete_consumer(void *base, void *other, uint32_t flag) {
    /* These direct root accesses survive alias-state widening. */
    uintptr_t result = LOAD32(base, 0) + LOAD32(base, 4) + LOAD32(base, 8);
    void *cursor;
    if (flag) cursor = base;
    else cursor = other;
    /* This fourth array element depends on the branch-joined alias state. */
    return result + LOAD32(cursor, 12) + global_flow_observe_pointer(cursor);
}

NOINLINE uintptr_t global_flow_insufficient_consumer(void *base, void *other, uint32_t flag) {
    uintptr_t result = LOAD32(base, 0);
    void *cursor;
    if (flag) cursor = base;
    else cursor = other;
    return result + LOAD32(cursor, 4) + global_flow_observe_pointer(cursor);
}

NOINLINE uintptr_t global_flow_empty_consumer(void *base, void *other, uint32_t flag) {
    void *cursor;
    if (flag) cursor = base;
    else cursor = other;
    /* The parameter is scanned and its address flows, but no object is loaded. */
    return global_flow_observe_pointer(cursor) + flag;
}

NOINLINE void global_flow_complete_entry(void) {
    result_sink ^= global_flow_complete_consumer(g_flow_complete, unrelated_storage, branch_flag);
}
NOINLINE void global_flow_insufficient_entry(void) {
    result_sink ^= global_flow_insufficient_consumer(g_flow_insufficient, unrelated_storage, branch_flag);
}
NOINLINE void global_flow_empty_entry(void) {
    result_sink ^= global_flow_empty_consumer(g_flow_empty, unrelated_storage, branch_flag);
}

int main(int argc, char **argv) {
    (void)argv;
    branch_flag = (uint32_t)argc;
    global_flow_complete_entry();
    global_flow_insufficient_entry();
    global_flow_empty_entry();
    return (int)result_sink;
}
