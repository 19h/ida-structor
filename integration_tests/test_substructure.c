/**
 * Test: Complex call graph with substructure passing
 *
 * Call graph:
 *   A (main) calls B and C
 *   B calls D
 *   D calls C
 *
 * Structure: 24 bytes total
 *   offset 0x00: next pointer (accessed by A, B, D)
 *   offset 0x08: prev pointer (accessed by A, B)
 *   offset 0x10: data int (accessed by A, C, D)
 *   offset 0x14: flags int (accessed by A, C)
 *
 * C receives a SUBSTRUCTURE (struct + 0x10), so it sees:
 *   offset 0x00 (actually 0x10): data int
 *   offset 0x04 (actually 0x14): flags int
 *
 * Expected: When structor is invoked on C's parameter, it should
 * discover ALL four functions and reconstruct the FULL struct.
 */

#include <stdio.h>
#include <stdint.h>

typedef struct Node {
    struct Node* next;  // 0x00
    struct Node* prev;  // 0x08
    int data;           // 0x10
    int flags;          // 0x14
} Node;

// C: Receives substructure (pointer to data field)
// From C's perspective: offset 0 is data, offset 4 is flags
__attribute__((noinline))
int process_data(void* data_ptr) {
    int data = *(int*)data_ptr;                    // offset 0 (actually 0x10)
    int flags = *(int*)((char*)data_ptr + 4);      // offset 4 (actually 0x14)
    printf("C: data=%d, flags=%d\n", data, flags);
    return data + flags;
}

// D: Receives full struct, accesses next and data, calls C with substructure
__attribute__((noinline))
int process_node_d(void* node) {
    void* next = *(void**)node;                    // offset 0x00 (next)
    int data = *(int*)((char*)node + 0x10);        // offset 0x10 (data)
    printf("D: next=%p, data=%d\n", next, data);

    // Call C with pointer to data field (struct + 0x10)
    return process_data((char*)node + 0x10);
}

// B: Receives full struct, accesses next and prev, calls D
__attribute__((noinline))
void setup_links(void* node) {
    void* next = *(void**)node;                    // offset 0x00 (next)
    void* prev = *(void**)((char*)node + 8);       // offset 0x08 (prev)
    printf("B: next=%p, prev=%p\n", next, prev);

    // Call D with full struct
    process_node_d(node);
}

// A (main): Has full struct, calls B and C
int main() {
    Node n1 = {NULL, NULL, 42, 0x1};
    Node n2 = {NULL, NULL, 100, 0x2};

    n1.next = &n2;
    n2.prev = &n1;

    printf("A: Full struct at %p\n", (void*)&n1);
    printf("A: next=%p, prev=%p, data=%d, flags=%d\n",
           (void*)n1.next, (void*)n1.prev, n1.data, n1.flags);

    // Call B with full struct
    setup_links(&n1);

    // Call C with substructure (struct + 0x10)
    int result = process_data((char*)&n1 + 0x10);

    printf("Result: %d\n", result);
    return 0;
}
