/**
 * Test 6: Structure with function pointer callbacks
 * Expected synthesis: function pointer at 0x0, void* at 0x8, int at 0x10
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

typedef void (*callback_t)(void* ctx, int value);

typedef struct {
    callback_t callback;  // 0x00
    void* context;        // 0x08
    int state;            // 0x10
    int flags;            // 0x14
} Handler;

void my_callback(void* ctx, int value) {
    printf("Callback called: ctx=%p, value=%d\n", ctx, value);
}

// Call the function pointer in the struct
__attribute__((noinline))
void invoke_handler(void* handler_ptr) {
    // Get function pointer at offset 0
    callback_t cb = *(callback_t*)handler_ptr;

    // Get context at offset 8
    void* ctx = *(void**)((char*)handler_ptr + 8);

    // Get state at offset 0x10
    int state = *(int*)((char*)handler_ptr + 0x10);

    // Call the function pointer
    if (cb) {
        cb(ctx, state);
    }
}

// Set up the handler
__attribute__((noinline))
void setup_handler(void* handler_ptr, void* cb, void* ctx, int initial_state) {
    *(void**)handler_ptr = cb;
    *(void**)((char*)handler_ptr + 8) = ctx;
    *(int*)((char*)handler_ptr + 0x10) = initial_state;
    *(int*)((char*)handler_ptr + 0x14) = 0;
}

// Update state and invoke
__attribute__((noinline))
void update_and_invoke(void* handler_ptr, int new_state) {
    *(int*)((char*)handler_ptr + 0x10) = new_state;
    invoke_handler(handler_ptr);
}

int main() {
    Handler h;
    setup_handler(&h, (void*)my_callback, (void*)0xCAFE, 42);
    invoke_handler(&h);
    update_and_invoke(&h, 100);
    return 0;
}
