/**
 * Test 1: Simple structure with basic field accesses
 * Expected synthesis: struct with int at 0x0, int at 0x8, ptr at 0x10
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

typedef struct {
    int field_0;
    int padding;
    long field_8;
    void* field_10;
} SimpleStruct;

// Function with clear structure accesses via pointer arithmetic
__attribute__((noinline))
void process_simple(void* ptr) {
    // Access field at offset 0 (int)
    int a = *(int*)ptr;

    // Access field at offset 8 (long)
    long b = *(long*)((char*)ptr + 8);

    // Access field at offset 0x10 (pointer)
    void* c = *(void**)((char*)ptr + 0x10);

    printf("a=%d, b=%ld, c=%p\n", a, b, c);
}

// Function with writes to structure
__attribute__((noinline))
void init_simple(void* ptr) {
    *(int*)ptr = 42;
    *(long*)((char*)ptr + 8) = 0x123456789ABCDEFLL;
    *(void**)((char*)ptr + 0x10) = (void*)0xDEADBEEF;
}

int main(int argc, char** argv) {
    SimpleStruct s;
    init_simple(&s);
    process_simple(&s);
    return 0;
}
