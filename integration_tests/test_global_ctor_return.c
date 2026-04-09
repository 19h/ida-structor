#include <stdint.h>
#include <stdio.h>

static volatile uint64_t sink;
static uint8_t g_session[0x50];

#define S_ID       0x00
#define S_STATE    0x04
#define S_HEAD     0x08
#define S_LENGTH   0x10
#define S_CONTEXT  0x18
#define S_CRC      0x20
#define S_SUB      0x28

#define SUB_KIND   0x00
#define SUB_VALUE  0x08

__attribute__((noinline))
void *session_storage(void) {
    return g_session;
}

__attribute__((noinline))
void session_ctor(void *dst, uint64_t token) {
    uint8_t *b = (uint8_t *)dst;
    *(uint32_t *)(b + S_ID) = 0x51534553U;
    *(uint32_t *)(b + S_STATE) = 0x21U;
    *(uint64_t *)(b + S_HEAD) = token;
    *(uint64_t *)(b + S_LENGTH) = 0x40ULL;
    *(void **)(b + S_CONTEXT) = dst;
    *(uint32_t *)(b + S_CRC) = 0xDEADBEEFU;

    uint8_t *sub = b + S_SUB;
    *(uint32_t *)(sub + SUB_KIND) = 3U;
    *(uint64_t *)(sub + SUB_VALUE) = token ^ 0xAAAA5555AAAA5555ULL;
}

__attribute__((noinline))
void session_ctor_wrapper(void *dst) {
    session_ctor(dst, 0x1122334455667788ULL);
}

__attribute__((noinline))
void init_session(void) {
    void *slot = session_storage();
    session_ctor_wrapper(slot);
}

__attribute__((noinline))
void consume_session_sub(void *sub) {
    uint8_t *b = (uint8_t *)sub;
    sink ^= *(uint32_t *)(b + SUB_KIND);
    sink ^= *(uint64_t *)(b + SUB_VALUE);
}

__attribute__((noinline))
void consume_session(void) {
    uint8_t *b = (uint8_t *)session_storage();
    sink ^= *(uint32_t *)(b + S_ID);
    sink ^= *(uint64_t *)(b + S_HEAD);
    sink ^= *(uint32_t *)(b + S_CRC);
    sink ^= (uint64_t)(uintptr_t)*(void **)(b + S_CONTEXT);
    consume_session_sub(b + S_SUB);
}

int main(void) {
    init_session();
    consume_session();
    printf("sink=%llx\n", (unsigned long long)sink);
    return 0;
}
