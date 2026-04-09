#include <stdint.h>
#include <stdio.h>

static volatile uint64_t sink;
static uint8_t g_scratch[0x80];

__attribute__((noinline))
void fill_scratch(uint32_t seed) {
    for (uint32_t i = 0; i < 64U; ++i) {
        uint32_t slot = (i * 5U + seed) & 0x3FU;
        g_scratch[slot] = (uint8_t)(seed + i * 3U);
    }
}

__attribute__((noinline))
void scramble_scratch(uint32_t stride) {
    for (uint32_t i = 0; i < 64U; i += stride) {
        uint32_t slot = (i ^ (stride * 7U)) & 0x3FU;
        g_scratch[slot] ^= (uint8_t)(i + stride);
    }
}

__attribute__((noinline))
uint64_t checksum_scratch(uint32_t stride) {
    uint64_t acc = 0;
    for (uint32_t i = 0; i < 64U; i += stride) {
        uint32_t slot = (i * 3U + stride) & 0x3FU;
        acc = (acc << 1) ^ g_scratch[slot];
    }
    return acc;
}

int main(void) {
    fill_scratch(9U);
    scramble_scratch(3U);
    sink ^= checksum_scratch(5U);
    printf("sink=%llx\n", (unsigned long long)sink);
    return 0;
}
