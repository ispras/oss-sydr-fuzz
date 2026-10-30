#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

static int deep3(const uint8_t *d, size_t n) {
    if (n < 16) return 0;

    if (((d[8] + d[9]) & 0xFF) != 150) return 0;
    if ((d[10] ^ d[11]) != 0x55) return 0;
    if ((int)d[12] - (int)d[13] != 7) return 0;
    if ((d[14] | d[15]) != 0x7F) return 0;

    abort();
    return 1;
}

static int deep2(const uint8_t *d, size_t n) {
    if (n < 8) return 0;

    int state = 0;
    for (size_t i = 0; i < 4; i++) {
        switch (state) {
            case 0:
                state = (d[i] % 3 == 1) ? 1 : 4;
                break;
            case 1:
                state = ((d[i] ^ i) & 1) ? 2 : 5;
                break;
            case 2:
                state = (d[i] > 50 && d[i] < 100) ? 3 : 6;
                break;
            case 3:
                state = ((d[i] + i) % 5 == 0) ? 7 : 8;
                break;
            default:
                state = 99;
                break;
        }
        if (state == 99) return 0;
    }

    if (state != 7 && state != 8) return 0;

    if (((d[0] + d[1]) ^ d[2]) != 0x55) return 0;
    if (((d[3] * 3 + d[4]) & 0xFF) != 0x91) return 0;
    if ((d[5] - d[6] + d[7]) != 44) return 0;

    return deep3(d, n);
}

static int deep1(const uint8_t *d, size_t n) {
    if (n < 4) return 0;
    uint32_t s = 0;
    for (size_t i = 0; i < 4; i++)
        s += d[i];
    if (s != 210) return 0;
    if ((d[0] < d[1] && d[1] < d[2] && d[2] > d[3]) == 0) return 0;
    return deep2(d, n);
}

int main(void) {
    uint8_t buf[64];
    size_t n = fread(buf, 1, sizeof(buf), stdin);
    if (n == 0) return 0;
    if (n > 48) return 0;
    deep1(buf, n);
    return 0;
}
