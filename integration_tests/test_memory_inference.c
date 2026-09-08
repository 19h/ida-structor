#include <stdint.h>

volatile double memory_inference_double = 3.25;
volatile float memory_inference_float = 1.25f;
volatile uint64_t memory_inference_integer = 0x123456789abcdef0ULL;

__attribute__((noinline)) double memory_inference_globals(void) {
    return memory_inference_double + memory_inference_float;
}

__attribute__((noinline)) double memory_inference_local_pointer(const volatile double* pointer) {
    return *pointer;
}

__attribute__((noinline)) const volatile double* memory_inference_address_only(void) {
    return &memory_inference_double;
}

__attribute__((noinline)) uint64_t memory_inference_partial_storage(void) {
    return memory_inference_integer;
}

int main(void) {
    return (int)(memory_inference_globals() +
        memory_inference_local_pointer(memory_inference_address_only()) +
        (double)memory_inference_partial_storage());
}
