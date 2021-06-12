/*****************************************************************************
 *   (c) 2020 Ledger SAS.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *****************************************************************************/

#include <stddef.h>     // size_t
#include <stdint.h>     // int*_t, uint*_t
#include <string.h>     // strncpy, memmove
#include <stdbool.h>    // bool
#include "../macros.h"  // ASSERT
#include "../instruction/uint256.h"

#include "format.h"

bool format_i64(char *dst, size_t dst_len, const int64_t value) {
    char temp[] = "-9223372036854775808";

    char *ptr = temp;
    int64_t num = value;
    int sign = 1;

    if (value < 0) {
        sign = -1;
    }

    while (num != 0) {
        *ptr++ = '0' + (num % 10) * sign;
        num /= 10;
    }

    if (value < 0) {
        *ptr++ = '-';
    } else if (value == 0) {
        *ptr++ = '0';
    }

    int distance = (ptr - temp) + 1;

    if ((int) dst_len < distance) {
        return false;
    }

    size_t index = 0;

    while (--ptr >= temp) {
        dst[index++] = *ptr;
    }

    dst[index] = '\0';

    return true;
}

bool format_u64(char *out, size_t outLen, uint64_t in) {
    uint8_t i = 0;

    if (outLen == 0) {
        return false;
    }
    outLen--;

    while (in > 9) {
        out[i] = in % 10 + '0';
        in /= 10;
        i++;
        if (i + 1 > outLen) {
            return false;
        }
    }
    out[i] = in + '0';
    out[i + 1] = '\0';

    uint8_t j = 0;
    char tmp;

    // revert the string
    while (j < i) {
        // swap out[j] and out[i]
        tmp = out[j];
        out[j] = out[i];
        out[i] = tmp;

        i--;
        j++;
    }
    return true;
}

bool format_fpu64(char *dst, size_t dst_len, const uint64_t value, uint8_t decimals) {
    char buffer[21] = {0};

    if (!format_u64(buffer, sizeof(buffer), value)) {
        return false;
    }

    size_t digits = strlen(buffer);

    if (digits <= decimals) {
        if (dst_len <= 2 + decimals - digits) {
            return false;
        }
        *dst++ = '0';
        *dst++ = '.';
        for (uint16_t i = 0; i < decimals - digits; i++, dst++) {
            *dst = '0';
        }
        dst_len -= 2 + decimals - digits;
        strncpy(dst, buffer, dst_len);
    } else {
        if (dst_len <= digits + 1 + decimals) {
            return false;
        }

        const size_t shift = digits - decimals;
        memmove(dst, buffer, shift);
        dst[shift] = '.';
        strncpy(dst + shift + 1, buffer + shift, decimals);
    }

    return true;
}

int format_hex(const uint8_t *in, size_t in_len, char *out, size_t out_len) {
    if (out_len < 2 * in_len + 1) {
        return -1;
    }

    const char hex[] = "0123456789ABCDEF";
    size_t i = 0;
    int written = 0;

    while (i < in_len && (i * 2 + (2 + 1)) <= out_len) {
        uint8_t high_nibble = (in[i] & 0xF0) >> 4;
        *out = hex[high_nibble];
        out++;

        uint8_t low_nibble = in[i] & 0x0F;
        *out = hex[low_nibble];
        out++;

        i++;
        written += 2;
    }

    *out = '\0';

    return written + 1;
}

// Divide "number" of length "length" by "divisor" in place, returning remainder
static uint8_t divmod(uint8_t *number, uint16_t length, uint8_t divisor) {
    uint8_t remainder = 0;
    for (uint16_t i = 0; i < length; i++) {
        uint16_t temp = remainder * 256 + number[i];
        number[i] = (uint8_t) (temp / divisor);
        remainder = temp % divisor;
    }
    return remainder;
}

// Returns true if first "length" bytes of "bytes" are zero, false otherwise
static bool is_all_zero(uint8_t *bytes, uint16_t length) {
    for (int i = 0; i < length; ++i) {
        if (bytes[i] != 0) {
            return false;
        }
    }
    return true;
}

// Swap element at index "i" with element at index "j" in "array"
static void swap(char *array, uint16_t i, uint16_t j) {
    char temp = array[i];
    array[i] = array[j];
    array[j] = temp;
}

// Reverse the first "length" elements of "array"
static void reverse(char *array, int length) {
    uint16_t swapLen = length / 2;
    uint16_t last = length - 1;
    for (uint16_t i = 0; i < swapLen; ++i) {
        swap(array, i, last - i);
    }
}

/**
 * @brief Formats bytes as number string with radix \p base.
 *
 * This method \em mutates provided bytes \p in, converts the digits into base \p base and put the
 * resulting length in \p len. Returns whether conversion was successful or not.
 *
 * @param[in] in Bytes to mutate and format into digits of radix \p base.
 * @param[in,out] len First specifies length of passed in bytes buffer, will be overwritten with
 * actual length.
 * @param[out] out Resulting byte buffer.
 * @param[in] base The radix to convert digits of \p in bytes into.
 * @return true if conversion was succesful.
 * @return false if conversion was unsuccesful.
 */
static bool convert_byte_buffer_into_digits_with_base(uint8_t *in,
                                                      size_t *len,
                                                      char *out,
                                                      uint8_t base) {
    const size_t in_len = *len;
    size_t de_facto_length = 0;
    while (!is_all_zero(in, in_len)) {
        if (de_facto_length + 1 > in_len) {
            PRINTF("Failed to convert, result will not fit");
            return false;
        }

        // buffer[de_facto_length++] = '0' + divmod(bytes, length, base);
        out[de_facto_length++] = divmod(in, in_len, base);
    }
    ASSERT(in_len >= de_facto_length, "Result did not fit");
    reverse(out, de_facto_length);

    *len = de_facto_length;

    return true;
}

bool convert_byte_buffer_into_decimal(const uint8_t *in,
                                      const size_t in_len,
                                      uint8_t *tmp,
                                      const size_t tmp_len,
                                      char *out,
                                      size_t *out_len) {
    ASSERT(tmp_len >= in_len, "'in' bytes will not fit in 'tmp'.");
    memmove(tmp, in, in_len);
    size_t actual_len = tmp_len;

    if (!convert_byte_buffer_into_digits_with_base(tmp, &actual_len, out, 10)) {
        return false;
    }

    if (actual_len > *out_len) {
        return false;
    }
    *out_len = actual_len;

    uint8_t ascii_offset_decimal = '0';
    for (unsigned int digit_index = 0; digit_index < actual_len; ++digit_index) {
        out[digit_index] += ascii_offset_decimal;
    }
    out[actual_len] = '\0';  // NULL terminate

    return true;
}

/**
 * @brief Formats a UInt256 as a decimal string
 *
 * @param[int] uint256
 * @param[out] out will contain a decimal string
 * @param[in] out_len length of \p out.
 * @return true If was successful.
 * @return false If failed.
 */
bool to_string_uint256(uint256_t *uint256, char *out, const size_t out_len) {
    uint32_t base10 = 10;
    return tostring256(uint256, base10, out, (uint32_t) out_len);
}

void print_uint256(uint256_t *uint256) {
    char amount[UINT256_DEC_STRING_MAX_LENGTH + 1] = {0};

    if (!to_string_uint256(uint256, amount, sizeof(amount))) {
        PRINTF("Failed to print uint256");
        return;
    }

    PRINTF("%s\n", amount);
}