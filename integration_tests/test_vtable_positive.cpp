/**
 * Test for positive VTable detection
 * Uses direct vtable calls without intermediate variables
 */

#include <cstdio>
#include <cstdint>

// Function that calls through vtable directly AND accesses other fields
__attribute__((noinline))
void call_vtable_direct(void* obj) {
    // Access vtable pointer at offset 0 and call slot 0
    // Pattern: (*((void (**)(void*))*(void**)obj))(obj)
    // This is: obj->vtable[0](obj)
    typedef void (*vfunc_t)(void*);

    // Direct vtable call - slot 0
    vfunc_t f0 = ((vfunc_t*)(*(void**)obj))[0];
    f0(obj);

    // Direct vtable call - slot 1
    vfunc_t f1 = ((vfunc_t*)(*(void**)obj))[1];
    f1(obj);

    // Access data at offset 8
    int data = *(int*)((char*)obj + 8);
    printf("data: %d\n", data);

    // Access data at offset 12
    int data2 = *(int*)((char*)obj + 12);
    printf("data2: %d\n", data2);

    // Access pointer at offset 16
    void* ptr = *(void**)((char*)obj + 16);
    printf("ptr: %p\n", ptr);
}

// More aggressive pattern - inline vtable calls
__attribute__((noinline))
int call_multiple_slots(void* obj, int arg) {
    // Call slot 2 with argument
    typedef int (*slot2_t)(void*, int);
    slot2_t s2 = ((slot2_t*)(*(void**)obj))[2];
    int r1 = s2(obj, arg);

    // Call slot 3 with argument
    slot2_t s3 = ((slot2_t*)(*(void**)obj))[3];
    int r2 = s3(obj, arg * 2);

    // Access flags at offset 24
    long flags = *(long*)((char*)obj + 24);

    return r1 + r2 + flags;
}

// Dummy class implementation for the test
class TestClass {
public:
    void* vtable;       // offset 0
    int data;           // offset 8
    int data2;          // offset 12
    void* ptr;          // offset 16
    long flags;         // offset 24

    static void slot0(void* self) { printf("slot0 called\n"); }
    static void slot1(void* self) { printf("slot1 called\n"); }
    static int slot2(void* self, int x) { return x + 1; }
    static int slot3(void* self, int x) { return x * 2; }
};

typedef void (*vfunc_void)(void*);
typedef int (*vfunc_int)(void*, int);

// VTable for TestClass
void* test_vtable[] = {
    (void*)TestClass::slot0,
    (void*)TestClass::slot1,
    (void*)TestClass::slot2,
    (void*)TestClass::slot3
};

int main() {
    TestClass obj;
    obj.vtable = test_vtable;
    obj.data = 42;
    obj.data2 = 100;
    obj.ptr = (void*)0xDEADBEEF;
    obj.flags = 0xFF00FF;

    call_vtable_direct(&obj);
    int result = call_multiple_slots(&obj, 10);
    printf("result: %d\n", result);

    return 0;
}
