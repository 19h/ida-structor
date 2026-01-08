/**
 * Test 4: Mixed read/write accesses, various sizes
 * Expected synthesis: byte at 0x0, short at 0x2, int at 0x4, long at 0x8, float at 0x10
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

typedef struct {
    uint8_t  byte_field;    // 0x00
    uint8_t  pad1;          // 0x01
    uint16_t short_field;   // 0x02
    uint32_t int_field;     // 0x04
    uint64_t long_field;    // 0x08
    float    float_field;   // 0x10
    float    float_field2;  // 0x14
    double   double_field;  // 0x18
} MixedStruct;

// Read various field sizes
__attribute__((noinline))
void read_mixed(void* ptr) {
    uint8_t b = *(uint8_t*)ptr;
    uint16_t s = *(uint16_t*)((char*)ptr + 2);
    uint32_t i = *(uint32_t*)((char*)ptr + 4);
    uint64_t l = *(uint64_t*)((char*)ptr + 8);
    float f = *(float*)((char*)ptr + 0x10);
    double d = *(double*)((char*)ptr + 0x18);

    printf("byte=%u, short=%u, int=%u, long=%llu, float=%f, double=%f\n",
           b, s, i, l, f, d);
}

// Write various field sizes
__attribute__((noinline))
void write_mixed(void* ptr) {
    *(uint8_t*)ptr = 0x42;
    *(uint16_t*)((char*)ptr + 2) = 0x1234;
    *(uint32_t*)((char*)ptr + 4) = 0xDEADBEEF;
    *(uint64_t*)((char*)ptr + 8) = 0x123456789ABCDEFULL;
    *(float*)((char*)ptr + 0x10) = 3.14159f;
    *(double*)((char*)ptr + 0x18) = 2.718281828;
}

// Read-modify-write pattern
__attribute__((noinline))
void modify_mixed(void* ptr) {
    uint32_t* int_ptr = (uint32_t*)((char*)ptr + 4);
    *int_ptr = *int_ptr + 1;  // Read and write

    float* float_ptr = (float*)((char*)ptr + 0x10);
    *float_ptr = *float_ptr * 2.0f;
}

int main() {
    MixedStruct m;
    write_mixed(&m);
    read_mixed(&m);
    modify_mixed(&m);
    read_mixed(&m);
    return 0;
}
