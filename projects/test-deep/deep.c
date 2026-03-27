#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

int gate_bytes(const uint8_t *d, size_t n, size_t pos, uint8_t v) {
    if (n <= pos) return 0;
    if (d[pos] != v) return 0;
    return 1;
}

int deep4(const uint8_t *d, size_t n) {
    if (n < 16) return 0;
    if (!gate_bytes(d, n, 6, 'D')) return 0;
    if (!gate_bytes(d, n, 7, 'E')) return 0;
    if (!gate_bytes(d, n, 8, 'A')) return 0;
    if (!gate_bytes(d, n, 9, 'D')) return 0;

    if (((d[10] ^ 0x55) != 0x13)) return 0;
    if (((d[11] + 7) != 0x4E)) return 0;
    if (((d[12] - 3) != 0x45)) return 0;
    if (((d[13] ^ d[14]) != 0x03)) return 0;
    if (d[15] != 'I') return 0;

    abort();
    return 1;
}

int deep3(const uint8_t *d, size_t n) {
    if (n < 6) return 0;
    if (!gate_bytes(d, n, 3, '3')) return 0;
    uint32_t s = 0;
    s += d[4];
    s += d[5];
    if (s != ('M' + 'N')) return 0;
    if (d[4] != 'M') return 0;
    if (d[5] != 'N') return 0;
    return deep4(d, n);
}

int deep2(const uint8_t *d, size_t n) {
    if (n < 3) return 0;
    if (!gate_bytes(d, n, 1, '2')) return 0;
    if (!gate_bytes(d, n, 2, 'B')) return 0;
    return deep3(d, n);
}

int deep1(const uint8_t *d, size_t n) {
    if (n < 2) return 0;
    if (!gate_bytes(d, n, 0, '1')) return 0;
    return deep2(d, n);
}

int main(void) {
    uint8_t buf[128];
    size_t n = fread(buf, 1, sizeof(buf), stdin);
    if (n == 0)
        return 0;
    if (n > 120)
        return 0;
    if (buf[0] == '#')
        return 0;
    deep1(buf, n);
    return 0;
}
