#include <stdio.h>    // snprintf
#include <string.h>   // memset, strlen
#include <stddef.h>   // size_t
#include <stdint.h>   // uint*_t
#include <stdbool.h>  // bool

#include "bip32_path.h"
#include "../common/read.h"

bool bip32_path_read(const uint8_t *in, size_t in_len, bip32_path_t *out) {
    const uint8_t out_len = out->path_len;
    if (out_len == 0 || out_len > MAX_BIP32_PATH) {
        return false;
    }

    size_t offset = 0;

    for (size_t i = 0; i < out_len; i++) {
        if (offset + 4 > in_len) {
            return false;
        }
        out->path[i] = read_u32_be(in, offset);
        offset += 4;
    }

    return true;
}

bool bip32_path_format(const bip32_path_t *bip32_path, char *out, size_t out_len) {
    const uint8_t bip32_path_len = bip32_path->path_len;

    if (bip32_path_len == 0 || bip32_path_len > MAX_BIP32_PATH) {
        return false;
    }

    size_t offset = 0;

    for (uint16_t i = 0; i < bip32_path_len; i++) {
        size_t written;

        snprintf(out + offset, out_len - offset, "%d", bip32_path->path[i] & 0x7FFFFFFFu);
        written = strlen(out + offset);
        if (written == 0 || written >= out_len - offset) {
            explicit_bzero(out, out_len);
            return false;
        }
        offset += written;

        if ((bip32_path->path[i] & 0x80000000u) != 0) {
            snprintf(out + offset, out_len - offset, "'");
            written = strlen(out + offset);
            if (written == 0 || written >= out_len - offset) {
                explicit_bzero(out, out_len);
                return false;
            }
            offset += written;
        }

        if (i != bip32_path_len - 1) {
            snprintf(out + offset, out_len - offset, "/");
            written = strlen(out + offset);
            if (written == 0 || written >= out_len - offset) {
                explicit_bzero(out, out_len);
                return false;
            }
            offset += written;
        }
    }

    return true;
}
