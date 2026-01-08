/**
 * Test 3: Nested structure accesses and arrays
 * Expected synthesis: pointers at 0x0 and 0x8, array of ints starting at 0x10
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

typedef struct Inner {
    int x;
    int y;
} Inner;

typedef struct Outer {
    Inner* inner_ptr;      // 0x00
    void* data;            // 0x08
    int array[4];          // 0x10 - 0x20
    long flags;            // 0x20
} Outer;

// Access through nested pointer
__attribute__((noinline))
void access_nested(void* ptr) {
    // Access inner_ptr at offset 0
    void* inner = *(void**)ptr;

    // Access data at offset 8
    void* data = *(void**)((char*)ptr + 8);

    // Access array elements at offsets 0x10, 0x14, 0x18, 0x1C
    int a0 = *(int*)((char*)ptr + 0x10);
    int a1 = *(int*)((char*)ptr + 0x14);
    int a2 = *(int*)((char*)ptr + 0x18);
    int a3 = *(int*)((char*)ptr + 0x1C);

    // Access flags at offset 0x20
    long flags = *(long*)((char*)ptr + 0x20);

    printf("inner=%p, data=%p, array=[%d,%d,%d,%d], flags=%lx\n",
           inner, data, a0, a1, a2, a3, flags);
}

// Modify array elements
__attribute__((noinline))
void modify_array(void* ptr, int idx, int value) {
    // Calculate array offset: 0x10 + idx * 4
    *(int*)((char*)ptr + 0x10 + idx * sizeof(int)) = value;
}

int main() {
    Outer o;
    Inner i = {10, 20};
    o.inner_ptr = &i;
    o.data = (void*)0xCAFEBABE;
    o.array[0] = 1;
    o.array[1] = 2;
    o.array[2] = 3;
    o.array[3] = 4;
    o.flags = 0xFF00FF00;

    access_nested(&o);
    modify_array(&o, 2, 999);
    access_nested(&o);

    return 0;
}
