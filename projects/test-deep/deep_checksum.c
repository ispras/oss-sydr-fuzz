#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

int main(void) {
    uint8_t b[32];
    size_t n = fread(b, 1, sizeof(b), stdin);
    if (n < 12) return 0;

    if (((b[0] * 7 + b[1] * 13) & 0xFF) != 0x42) return 0;
    if (((b[2] * 5) ^ (b[3] + 11)) != 0x91) return 0;
    if (((b[4] + b[5] * 9) & 0xFF) != 0xA5) return 0;
    if (((b[6] ^ b[7] ^ b[8]) & 0xFF) != 0x5C) return 0;
    if (((b[9] * 3 - b[10]) & 0xFF) != 0x17) return 0;
    if (((b[11] + b[0] + b[3]) & 0xFF) != 0x77) return 0;

    abort();
    return 0;
}
