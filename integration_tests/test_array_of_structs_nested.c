#include <stdint.h>
#include <stdio.h>

static volatile uint64_t sink;

struct PacketEntry {
    uint32_t kind;
    uint8_t bytes[4];
    uint16_t values[2];
};

struct PacketTable {
    uint32_t count;
    uint32_t mode;
    struct PacketEntry items[3];
    uint8_t footer[2];
};

__attribute__((noinline))
void init_packets(void *p) {
    uint8_t *b = (uint8_t *)p;
    *(uint32_t *)(b + 0x00) = 3;
    *(uint32_t *)(b + 0x04) = 7;

    *(uint32_t *)(b + 0x08) = 100;
    b[0x0C] = 1; b[0x0D] = 2; b[0x0E] = 3; b[0x0F] = 4;
    *(uint16_t *)(b + 0x10) = 11; *(uint16_t *)(b + 0x12) = 12;

    *(uint32_t *)(b + 0x14) = 200;
    b[0x18] = 5; b[0x19] = 6; b[0x1A] = 7; b[0x1B] = 8;
    *(uint16_t *)(b + 0x1C) = 21; *(uint16_t *)(b + 0x1E) = 22;

    *(uint32_t *)(b + 0x20) = 300;
    b[0x24] = 9; b[0x25] = 10; b[0x26] = 11; b[0x27] = 12;
    *(uint16_t *)(b + 0x28) = 31; *(uint16_t *)(b + 0x2A) = 32;

    b[0x2C] = 0xAA;
    b[0x2D] = 0xBB;
}

__attribute__((noinline))
void read_packets(void *p) {
    uint8_t *b = (uint8_t *)p;
    sink ^= *(uint32_t *)(b + 0x00);
    sink ^= *(uint32_t *)(b + 0x04);
    sink ^= *(uint32_t *)(b + 0x08);
    sink ^= *(uint16_t *)(b + 0x10);
    sink ^= *(uint32_t *)(b + 0x14);
    sink ^= *(uint16_t *)(b + 0x1C);
    sink ^= *(uint32_t *)(b + 0x20);
    sink ^= *(uint16_t *)(b + 0x28);
}

__attribute__((noinline))
void write_packet_byte(void *p, int idx, uint8_t value) {
    uint8_t *b = (uint8_t *)p;
    *(uint8_t *)(b + 0x0C + idx * 12) = value;
}

__attribute__((noinline))
void read_footer(void *p) {
    uint8_t *b = (uint8_t *)p;
    sink ^= b[0x2C];
    sink ^= b[0x2D];
}

int main(void) {
    struct PacketTable table;
    init_packets(&table);
    read_packets(&table);
    write_packet_byte(&table, 1, 0xEE);
    read_footer(&table);
    printf("sink=%llx\n", (unsigned long long)sink);
    return 0;
}
