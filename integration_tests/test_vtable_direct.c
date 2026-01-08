/**
 * Test: Direct vtable field accesses
 * This creates a pattern where multiple fields are accessed
 * directly from the same base pointer, including a vtable-like
 * first field (function pointer array).
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

// Simulated object layout:
// offset 0x00: vtable pointer (function pointer array)
// offset 0x08: data1 (int)
// offset 0x0C: data2 (int)
// offset 0x10: data3 (pointer)
// offset 0x18: data4 (long)

// Access multiple fields directly from the same pointer
__attribute__((noinline))
void access_object_fields(void* obj) {
    // Access field at offset 0 (vtable pointer) - read
    void** vtable = *(void***)obj;

    // Access field at offset 8 (data1) - read
    int data1 = *(int*)((char*)obj + 0x08);

    // Access field at offset 0x0C (data2) - read
    int data2 = *(int*)((char*)obj + 0x0C);

    // Access field at offset 0x10 (data3) - read
    void* data3 = *(void**)((char*)obj + 0x10);

    // Access field at offset 0x18 (data4) - read
    long data4 = *(long*)((char*)obj + 0x18);

    printf("vtable=%p, data1=%d, data2=%d, data3=%p, data4=%ld\n",
           vtable, data1, data2, data3, data4);
}

// Modify multiple fields
__attribute__((noinline))
void modify_object_fields(void* obj, int new_data1, int new_data2) {
    // Write to field at offset 8
    *(int*)((char*)obj + 0x08) = new_data1;

    // Write to field at offset 0x0C
    *(int*)((char*)obj + 0x0C) = new_data2;

    // Write to field at offset 0x18
    *(long*)((char*)obj + 0x18) = new_data1 + new_data2;
}

// Combined read-modify-write on multiple fields
__attribute__((noinline))
void increment_fields(void* obj) {
    // Read and increment data1
    int* p1 = (int*)((char*)obj + 0x08);
    *p1 = *p1 + 1;

    // Read and increment data2
    int* p2 = (int*)((char*)obj + 0x0C);
    *p2 = *p2 + 1;

    // Read data4 and store doubled value
    long* p4 = (long*)((char*)obj + 0x18);
    *p4 = *p4 * 2;
}

int main() {
    // Create a fake object
    void* fake_obj[4];
    fake_obj[0] = NULL;           // vtable
    fake_obj[1] = (void*)0x1234;  // data1 + data2
    fake_obj[2] = (void*)0xCAFE;  // data3
    fake_obj[3] = (void*)0xBEEF;  // data4

    access_object_fields(fake_obj);
    modify_object_fields(fake_obj, 100, 200);
    access_object_fields(fake_obj);
    increment_fields(fake_obj);
    access_object_fields(fake_obj);

    return 0;
}
