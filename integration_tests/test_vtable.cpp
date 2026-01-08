/**
 * Test 2: C++ class with virtual functions (vtable)
 * Expected synthesis: vtable pointer at offset 0, int at offset 8
 * VTable should have slots for destructor, method1, method2
 */

#include <cstdio>
#include <cstdlib>
#include <cstdint>

class Base {
public:
    int value;

    virtual ~Base() {
        printf("Base destructor, value=%d\n", value);
    }

    virtual void method1() {
        printf("Base::method1, value=%d\n", value);
    }

    virtual int method2(int x) {
        return value + x;
    }
};

class Derived : public Base {
public:
    int extra;

    ~Derived() override {
        printf("Derived destructor, extra=%d\n", extra);
    }

    void method1() override {
        printf("Derived::method1, extra=%d\n", extra);
    }

    int method2(int x) override {
        return extra * x;
    }
};

// Function that uses vtable calls without knowing the type
__attribute__((noinline))
void call_through_vtable(void* obj) {
    // vtable is at offset 0
    void** vtable = *(void***)obj;

    // Slot 0: destructor (we won't call it)
    // Slot 1: method1
    // Slot 2: method2

    // Call method1 (slot 1) - typical pattern: (*(vtable[1]))(obj)
    typedef void (*method1_t)(void*);
    method1_t m1 = (method1_t)vtable[1];
    m1(obj);

    // Call method2 (slot 2)
    typedef int (*method2_t)(void*, int);
    method2_t m2 = (method2_t)vtable[2];
    int result = m2(obj, 10);
    printf("method2 result: %d\n", result);
}

// Access value field (offset 8 due to vtable at 0)
__attribute__((noinline))
void access_value(void* obj) {
    int val = *(int*)((char*)obj + 8);
    printf("value: %d\n", val);
}

int main() {
    Derived* d = new Derived();
    d->value = 100;
    d->extra = 200;

    call_through_vtable(d);
    access_value(d);

    delete d;
    return 0;
}
