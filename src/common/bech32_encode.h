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

#ifndef _SEGWIT_ADDR_H_
#define _SEGWIT_ADDR_H_ 1

#include <stddef.h>  // size_t
#include <stdint.h>  //
#include <stdbool.h>

/**
 * @brief Bech32 encode data.
 *
 * Bech32 encodes (hrp || data), sets `data_len` to actual length of bech32 string,
 * if encoding was successful.
 *
 * @param[out] output
 *   Pointer to a buffer of size strlen(hrp) + data_len + 8 that
 *                will be updated to contain the null-terminated Bech32 string.
 * @param[in]  hrp
 *   Pointer to the null-terminated human readable part.
 * @param[in]  data
 *   Pointer to an array of 5-bit values.
 * @param[in,out] data_len
 *   Length of the data array.
 *
 * @return true If bech32 encoding was successful
 * @return false If bech32 encoding was unsuccessful
 *
 */
bool bech32_encode(char *output, const char *hrp, const uint8_t *data, size_t *data_len);

int convert_bits(uint8_t *out,
                 size_t *outlen,
                 int outBits,
                 const uint8_t *in,
                 size_t inLen,
                 int inBits,
                 int pad);

#endif
