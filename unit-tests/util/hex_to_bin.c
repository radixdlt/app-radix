#include "hex_to_bin.h"

// FROM: https://gist.github.com/vi/dd3b5569af8a26b97c8e20ae06e804cb
void hex_to_bin(const char *str, uint8_t *bytes, size_t blen) {
    uint8_t pos;
    uint8_t idx0;
    uint8_t idx1;

    // mapping of ASCII characters to hex values
    const uint8_t hashmap[] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,  // 01234567
        0x08, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // 89:;<=>?
        0x00, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x00,  // @ABCDEFG
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // HIJKLMNO
    };

    memset(bytes, 0, blen);
    for (pos = 0; ((pos < (blen * 2)) && (pos < strlen(str))); pos += 2) {
        idx0 = ((uint8_t) str[pos + 0] & 0x1F) ^ 0x10;
        idx1 = ((uint8_t) str[pos + 1] & 0x1F) ^ 0x10;
        bytes[pos / 2] = (uint8_t) (hashmap[idx0] << 4) | hashmap[idx1];
    };
}