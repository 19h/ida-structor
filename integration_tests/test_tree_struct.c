#include <stdint.h>
#include <stdio.h>

static volatile uint64_t sink;

struct TreeNode {
    uint32_t value;
    struct TreeNode *left;
    struct TreeNode *right;
    uint8_t color;
};

__attribute__((noinline))
void init_tree(struct TreeNode *root, struct TreeNode *left, struct TreeNode *right) {
    root->value = 10;
    root->left = left;
    root->right = right;
    root->color = 1;

    left->value = 20;
    left->left = 0;
    left->right = 0;
    left->color = 2;

    right->value = 30;
    right->left = 0;
    right->right = 0;
    right->color = 3;
}

__attribute__((noinline))
void sum_children(void *p) {
    uint8_t *b = (uint8_t *)p;
    sink ^= *(uint32_t *)(b + 0x00);
    sink ^= *(uint64_t *)(b + 0x08);
    sink ^= *(uint64_t *)(b + 0x10);
    sink ^= *(uint8_t *)(b + 0x18);
}

__attribute__((noinline))
void walk_two_levels(void *p) {
    struct TreeNode *n = (struct TreeNode *)p;
    sink ^= n->left->value;
    sink ^= n->right->value;
}

int main(void) {
    struct TreeNode root, left, right;
    init_tree(&root, &left, &right);
    sum_children(&root);
    walk_two_levels(&root);
    printf("sink=%llx\n", (unsigned long long)sink);
    return 0;
}
