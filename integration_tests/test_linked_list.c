/**
 * Test 5: Linked list node with self-referential pointer
 * Expected synthesis: pointer at 0x0 (next), pointer at 0x8 (prev), int at 0x10 (data)
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

typedef struct Node {
    struct Node* next;  // 0x00
    struct Node* prev;  // 0x08
    int data;           // 0x10
    int flags;          // 0x14
} Node;

// Traverse linked list
__attribute__((noinline))
void traverse_list(void* head) {
    void* current = head;
    int count = 0;

    while (current != NULL && count < 100) {
        // Read data at offset 0x10
        int data = *(int*)((char*)current + 0x10);
        printf("Node %d: data=%d\n", count, data);

        // Read next pointer at offset 0
        current = *(void**)current;
        count++;
    }
}

// Insert after a node
__attribute__((noinline))
void insert_after(void* node, void* new_node) {
    // Get old next
    void* old_next = *(void**)node;

    // Set new_node->next = old_next
    *(void**)new_node = old_next;

    // Set new_node->prev = node
    *(void**)((char*)new_node + 8) = node;

    // Set node->next = new_node
    *(void**)node = new_node;

    // Set old_next->prev = new_node (if exists)
    if (old_next) {
        *(void**)((char*)old_next + 8) = new_node;
    }
}

// Sum all data in list
__attribute__((noinline))
int sum_list(void* head) {
    void* current = head;
    int sum = 0;

    while (current) {
        sum += *(int*)((char*)current + 0x10);
        current = *(void**)current;
    }

    return sum;
}

int main() {
    Node n1 = {NULL, NULL, 10, 0};
    Node n2 = {NULL, NULL, 20, 0};
    Node n3 = {NULL, NULL, 30, 0};

    n1.next = &n2;
    n2.prev = &n1;
    n2.next = &n3;
    n3.prev = &n2;

    traverse_list(&n1);
    printf("Sum: %d\n", sum_list(&n1));

    return 0;
}
