/* Copyright (c) 2017 Pieter Wuille
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
#include <stdlib.h>
#include <string.h>

#include "bech32_encode.h"

uint32_t bech32_polymod_step(uint32_t pre) {
    uint8_t b = pre >> 25u;
    return ((pre & 0x1FFFFFFu) << 5u) ^ (-((b >> 0u) & 1u) & 0x3b6a57b2UL) ^
           (-((b >> 1u) & 1u) & 0x26508e6dUL) ^ (-((b >> 2u) & 1u) & 0x1ea119faUL) ^
           (-((b >> 3u) & 1u) & 0x3d4233ddUL) ^ (-((b >> 4u) & 1u) & 0x2a1462b3UL);
}

static const char* charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";

static const int8_t charset_rev[128] = {
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, 15, -1, 10, 17, 21, 20, 26, 30, 7,  5,  -1, -1, -1, -1, -1, -1, -1, 29,
    -1, 24, 13, 25, 9,  8,  23, -1, 18, 22, 31, 27, 19, -1, 1,  0,  3,  16, 11, 28, 12, 14,
    6,  4,  2,  -1, -1, -1, -1, -1, -1, 29, -1, 24, 13, 25, 9,  8,  23, -1, 18, 22, 31, 27,
    19, -1, 1,  0,  3,  16, 11, 28, 12, 14, 6,  4,  2,  -1, -1, -1, -1, -1};

bool bech32_encode(char* output, const char* hrp, const uint8_t* data, size_t* data_len) {
    uint32_t chk = 1;
    size_t i = 0;
    while (hrp[i] != 0) {
        char ch = hrp[i];
        if (ch < 33 || ch > 126) {
            return false;
        }

        if (ch >= 'A' && ch <= 'Z') return false;
        chk = bech32_polymod_step(chk) ^ (ch >> 5u);
        ++i;
    }
    if (i + 7 + *data_len > 90) return false;
    chk = bech32_polymod_step(chk);
    size_t actual_size = 0;
    while (*hrp != 0) {
        chk = bech32_polymod_step(chk) ^ (*hrp & 0x1fu);
        *(output++) = *(hrp++);
        actual_size++;
    }
    *(output++) = '1';
    actual_size++;
    for (i = 0; i < *data_len; ++i) {
        if (*data >> 5u) return false;
        chk = bech32_polymod_step(chk) ^ (*data);
        *(output++) = charset[*(data++)];
        actual_size++;
    }
    for (i = 0; i < 6; ++i) {
        chk = bech32_polymod_step(chk);
    }
    chk ^= 1;
    for (i = 0; i < 6; ++i) {
        *(output++) = charset[(chk >> ((5u - i) * 5u)) & 0x1fu];
        actual_size++;
    }
    *output = 0;
    actual_size++;  // for NULL terminator.
    *data_len = actual_size;
    return true;
}

int bech32_decode(char* hrp, uint8_t* data, size_t* data_len, const char* input) {
    uint32_t chk = 1;
    size_t i;
    size_t input_len = strlen(input);
    size_t hrp_len;
    int have_lower = 0, have_upper = 0;
    if (input_len < 8 || input_len > 90) {
        return 0;
    }
    *data_len = 0;
    while (*data_len < input_len && input[(input_len - 1) - *data_len] != '1') {
        ++(*data_len);
    }
    hrp_len = input_len - (1 + *data_len);
    if (1 + *data_len >= input_len || *data_len < 6) {
        return 0;
    }
    *(data_len) -= 6;
    for (i = 0; i < hrp_len; ++i) {
        char ch = input[i];
        if (ch < 33 || ch > 126) {
            return 0;
        }
        if (ch >= 'a' && ch <= 'z') {
            have_lower = 1;
        } else if (ch >= 'A' && ch <= 'Z') {
            have_upper = 1;
            ch = (ch - 'A') + 'a';
        }
        hrp[i] = ch;
        chk = bech32_polymod_step(chk) ^ (ch >> 5u);
    }
    hrp[i] = 0;
    chk = bech32_polymod_step(chk);
    for (i = 0; i < hrp_len; ++i) {
        chk = bech32_polymod_step(chk) ^ (input[i] & 0x1fu);
    }
    ++i;
    while (i < input_len) {
        int v = (input[i] & 0x80u) ? -1 : charset_rev[(int) input[i]];
        if (input[i] >= 'a' && input[i] <= 'z') have_lower = 1;
        if (input[i] >= 'A' && input[i] <= 'Z') have_upper = 1;
        if (v == -1) {
            return 0;
        }
        chk = bech32_polymod_step(chk) ^ v;
        if (i + 6 < input_len) {
            data[i - (1 + hrp_len)] = v;
        }
        ++i;
    }
    if (have_lower && have_upper) {
        return 0;
    }
    return chk == 1;
}

int convert_bits(uint8_t* out,
                 size_t* outlen,
                 int outBits,
                 const uint8_t* in,
                 size_t inLen,
                 int inBits,
                 int pad) {
    uint32_t val = 0;
    int bits = 0;
    uint32_t maxv = (((uint32_t) 1u) << outBits) - 1u;
    while (inLen--) {
        val = (val << inBits) | *(in++);
        bits += inBits;
        while (bits >= outBits) {
            bits -= outBits;
            out[(*outlen)++] = (val >> bits) & maxv;
        }
    }
    if (pad) {
        if (bits) {
            out[(*outlen)++] = (val << (outBits - bits)) & maxv;
        }
    } else if (((val << (outBits - bits)) & maxv) || bits >= inBits) {
        return 0;
    }
    return 1;
}