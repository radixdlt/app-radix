/*******************************************************************************
 *   Ledger Ethereum App
 *   (c) 2016-2019 Ledger
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
 ********************************************************************************/

// Taken from: https://github.com/LedgerHQ/app-ethereum/blob/master/src_common/uint256.c
// Adapted from https://github.com/calccrypto/uint256_t

#include <stdio.h>
#include <string.h>

#include "uint256.h"
#include "buffer.h"

#include "../bridge.h"

static const char HEXDIGITS[] = "0123456789abcdef";

static uint64_t readUint64BE(uint8_t *buffer) {
    return (((uint64_t) buffer[0]) << 56) | (((uint64_t) buffer[1]) << 48) |
           (((uint64_t) buffer[2]) << 40) | (((uint64_t) buffer[3]) << 32) |
           (((uint64_t) buffer[4]) << 24) | (((uint64_t) buffer[5]) << 16) |
           (((uint64_t) buffer[6]) << 8) | (((uint64_t) buffer[7]));
}

static void readu128BE(uint8_t *buffer, uint128_t *target) {
    UPPER_P(target) = readUint64BE(buffer);
    LOWER_P(target) = readUint64BE(buffer + 8);
}

static bool zero128(uint128_t *number) {
    return ((LOWER_P(number) == 0) && (UPPER_P(number) == 0));
}

static bool zero256(uint256_t *number) {
    return (zero128(&LOWER_P(number)) && zero128(&UPPER_P(number)));
}

static void copy128(uint128_t *target, const uint128_t *number) {
    UPPER_P(target) = UPPER_P(number);
    LOWER_P(target) = LOWER_P(number);
}

static void clear128(uint128_t *target) {
    UPPER_P(target) = 0;
    LOWER_P(target) = 0;
}

static void shiftl128(uint128_t *number, uint32_t value, uint128_t *target) {
    if (value >= 128) {
        clear128(target);
    } else if (value == 64) {
        UPPER_P(target) = LOWER_P(number);
        LOWER_P(target) = 0;
    } else if (value == 0) {
        copy128(target, number);
    } else if (value < 64) {
        UPPER_P(target) = (UPPER_P(number) << value) + (LOWER_P(number) >> (64 - value));
        LOWER_P(target) = (LOWER_P(number) << value);
    } else if ((128 > value) && (value > 64)) {
        UPPER_P(target) = LOWER_P(number) << (value - 64);
        LOWER_P(target) = 0;
    } else {
        clear128(target);
    }
}

static void shiftr128(uint128_t *number, uint32_t value, uint128_t *target) {
    if (value >= 128) {
        clear128(target);
    } else if (value == 64) {
        UPPER_P(target) = 0;
        LOWER_P(target) = UPPER_P(number);
    } else if (value == 0) {
        copy128(target, number);
    } else if (value < 64) {
        uint128_t result;
        UPPER(result) = UPPER_P(number) >> value;
        LOWER(result) = (UPPER_P(number) << (64 - value)) + (LOWER_P(number) >> value);
        copy128(target, &result);
    } else if ((128 > value) && (value > 64)) {
        LOWER_P(target) = UPPER_P(number) >> (value - 64);
        UPPER_P(target) = 0;
    } else {
        clear128(target);
    }
}

static void add128(const uint128_t *number1, const uint128_t *number2, uint128_t *target) {
    UPPER_P(target) = UPPER_P(number1) + UPPER_P(number2) +
                      ((LOWER_P(number1) + LOWER_P(number2)) < LOWER_P(number1));
    LOWER_P(target) = LOWER_P(number1) + LOWER_P(number2);
}

static void shiftl256(uint256_t *number, uint32_t value, uint256_t *target) {
    if (value >= 256) {
        clear256(target);
    } else if (value == 128) {
        copy128(&UPPER_P(target), &LOWER_P(number));
        clear128(&LOWER_P(target));
    } else if (value == 0) {
        copy256(target, number);
    } else if (value < 128) {
        uint128_t tmp1;
        uint128_t tmp2;
        uint256_t result;
        shiftl128(&UPPER_P(number), value, &tmp1);
        shiftr128(&LOWER_P(number), (128 - value), &tmp2);
        add128(&tmp1, &tmp2, &UPPER(result));
        shiftl128(&LOWER_P(number), value, &LOWER(result));
        copy256(target, &result);
    } else if ((256 > value) && (value > 128)) {
        shiftl128(&LOWER_P(number), (value - 128), &UPPER_P(target));
        clear128(&LOWER_P(target));
    } else {
        clear256(target);
    }
}

static void shiftr256(uint256_t *number, uint32_t value, uint256_t *target) {
    if (value >= 256) {
        clear256(target);
    } else if (value == 128) {
        copy128(&LOWER_P(target), &UPPER_P(number));
        clear128(&UPPER_P(target));
    } else if (value == 0) {
        copy256(target, number);
    } else if (value < 128) {
        uint128_t tmp1;
        uint128_t tmp2;
        uint256_t result;
        shiftr128(&UPPER_P(number), value, &UPPER(result));
        shiftr128(&LOWER_P(number), value, &tmp1);
        shiftl128(&UPPER_P(number), (128 - value), &tmp2);
        add128(&tmp1, &tmp2, &LOWER(result));
        copy256(target, &result);
    } else if ((256 > value) && (value > 128)) {
        shiftr128(&UPPER_P(number), (value - 128), &LOWER_P(target));
        clear128(&UPPER_P(target));
    } else {
        clear256(target);
    }
}

static uint32_t bits256(uint256_t *number) {
    uint32_t result = 0;
    if (!zero128(&UPPER_P(number))) {
        result = 128;
        uint128_t up;
        copy128(&up, &UPPER_P(number));
        while (!zero128(&up)) {
            shiftr128(&up, 1, &up);
            result++;
        }
    } else {
        uint128_t low;
        copy128(&low, &LOWER_P(number));
        while (!zero128(&low)) {
            shiftr128(&low, 1, &low);
            result++;
        }
    }
    return result;
}

static bool equal128(const uint128_t *number1, const uint128_t *number2) {
    return (UPPER_P(number1) == UPPER_P(number2)) && (LOWER_P(number1) == LOWER_P(number2));
}

static bool equal256(const uint256_t *number1, const uint256_t *number2) {
    return (equal128(&UPPER_P(number1), &UPPER_P(number2)) &&
            equal128(&LOWER_P(number1), &LOWER_P(number2)));
}

static bool gt128(const uint128_t *number1, const uint128_t *number2) {
    if (UPPER_P(number1) == UPPER_P(number2)) {
        return (LOWER_P(number1) > LOWER_P(number2));
    }
    return (UPPER_P(number1) > UPPER_P(number2));
}

static bool gte256(const uint256_t *number1, const uint256_t *number2) {
    return gt256(number1, number2) || equal256(number1, number2);
}

static void minus128(const uint128_t *number1, const uint128_t *number2, uint128_t *target) {
    UPPER_P(target) = UPPER_P(number1) - UPPER_P(number2) -
                      ((LOWER_P(number1) - LOWER_P(number2)) > LOWER_P(number1));
    LOWER_P(target) = LOWER_P(number1) - LOWER_P(number2);
}

static void or128(const uint128_t *number1, const uint128_t *number2, uint128_t *target) {
    UPPER_P(target) = UPPER_P(number1) | UPPER_P(number2);
    LOWER_P(target) = LOWER_P(number1) | LOWER_P(number2);
}

static void or256(const uint256_t *number1, const uint256_t *number2, uint256_t *target) {
    or128(&UPPER_P(number1), &UPPER_P(number2), &UPPER_P(target));
    or128(&LOWER_P(number1), &LOWER_P(number2), &LOWER_P(target));
}

static void divmod256(uint256_t *l, uint256_t *r, uint256_t *retDiv, uint256_t *retMod) {
    uint256_t copyd, adder, resDiv, resMod;
    uint256_t one;
    clear256(&one);
    UPPER(LOWER(one)) = 0;
    LOWER(LOWER(one)) = 1;
    uint32_t diffBits = bits256(l) - bits256(r);
    clear256(&resDiv);
    copy256(&resMod, l);
    if (gt256(r, l)) {
        copy256(retMod, l);
        clear256(retDiv);
    } else {
        shiftl256(r, diffBits, &copyd);
        shiftl256(&one, diffBits, &adder);
        if (gt256(&copyd, &resMod)) {
            shiftr256(&copyd, 1, &copyd);
            shiftr256(&adder, 1, &adder);
        }
        while (gte256(&resMod, r)) {
            if (gte256(&resMod, &copyd)) {
                minus256(&resMod, &copyd, &resMod);
                or256(&resDiv, &adder, &resDiv);
            }
            shiftr256(&copyd, 1, &copyd);
            shiftr256(&adder, 1, &adder);
        }
        copy256(retDiv, &resDiv);
        copy256(retMod, &resMod);
    }
}

static size_t pretty_print(char *input, uint32_t input_len, char *output) {
    size_t out_len = 0;
    uint32_t start;

    for (start = 0; start < input_len; start++) {
        if (input[start] == '0') {
            continue;
        }

        if (input[start] == '.') {
            start++;
        }

        break;
    }

    for (int j = (int) input_len - 1; start != input_len; j--) {
        output[out_len++] = input[j];
        start++;
    };

    output[out_len++] = '\0';

    return out_len;
}

bool to_string_uint256_get_len(const uint256_t *number,
                               char *out,
                               const size_t outLength,
                               size_t *actual_len) {
    uint256_t rDiv;
    uint256_t rMod;
    uint256_t base;
    copy256(&rDiv, number);
    clear256(&rMod);
    clear256(&base);
    UPPER(LOWER(base)) = 0;
    LOWER(LOWER(base)) = 10;
    uint32_t offset = 0;
    char buffer[UINT256_DEC_STRING_MAX_LENGTH + 2];  //+1 for \0 and +1 for '.'

    do {
        divmod256(&rDiv, &base, &rDiv, &rMod);
        buffer[offset++] = HEXDIGITS[(uint8_t) LOWER(LOWER(rMod))];

        if (offset == 18) {  // E-18
            buffer[offset++] = '.';
        }

    } while (offset < 20 || !zero256(&rDiv));

    if (offset > outLength) {
        return false;
    }

    *actual_len = pretty_print(buffer, offset, out);
    return true;
}

bool to_string_uint256(const uint256_t *uint256, char *out, const size_t out_len) {
    size_t discarded = out_len;
    return to_string_uint256_get_len(uint256, out, out_len, &discarded);
}

static const uint256_t ZERO;

bool is_uint256_greater_than_zero(const uint256_t *target) {
    return gt256(target, &ZERO);
}

void add256(const uint256_t *number1, const uint256_t *number2, uint256_t *target) {
    uint128_t tmp;
    add128(&UPPER_P(number1), &UPPER_P(number2), &UPPER_P(target));
    add128(&LOWER_P(number1), &LOWER_P(number2), &tmp);
    if (gt128(&LOWER_P(number1), &tmp)) {
        uint128_t one;
        UPPER(one) = 0;
        LOWER(one) = 1;
        add128(&UPPER_P(target), &one, &UPPER_P(target));
    }
    add128(&LOWER_P(number1), &LOWER_P(number2), &LOWER_P(target));
}

void minus256(const uint256_t *number1, const uint256_t *number2, uint256_t *target) {
    uint128_t tmp;
    minus128(&UPPER_P(number1), &UPPER_P(number2), &UPPER_P(target));
    minus128(&LOWER_P(number1), &LOWER_P(number2), &tmp);
    if (gt128(&tmp, &LOWER_P(number1))) {
        uint128_t one;
        UPPER(one) = 0;
        LOWER(one) = 1;
        minus128(&UPPER_P(target), &one, &UPPER_P(target));
    }
    minus128(&LOWER_P(number1), &LOWER_P(number2), &LOWER_P(target));
}

void readu256BE(uint8_t *buffer, uint256_t *target) {
    readu128BE(buffer, &UPPER_P(target));
    readu128BE(buffer + 16, &LOWER_P(target));
}

bool uint256_from_buffer(buffer_t *buffer, uint256_t *target) {
    uint8_t temp[UINT256_BYTE_COUNT];
    if (!buffer_move_fill_target(buffer, temp, UINT256_BYTE_COUNT)) {
        PRINTF("Failed to parse uint256 from buffer.\n");
        return false;
    }
    readu256BE(temp, target);
    return true;
}

void copy256(uint256_t *target, const uint256_t *number) {
    copy128(&UPPER_P(target), &UPPER_P(number));
    copy128(&LOWER_P(target), &LOWER_P(number));
}

void clear256(uint256_t *target) {
    clear128(&UPPER_P(target));
    clear128(&LOWER_P(target));
}

bool gt256(const uint256_t *number1, const uint256_t *number2) {
    if (equal128(&UPPER_P(number1), &UPPER_P(number2))) {
        return gt128(&LOWER_P(number1), &LOWER_P(number2));
    }
    return gt128(&UPPER_P(number1), &UPPER_P(number2));
}

/**
 * Unused functions.
 */
#if 0
static uint32_t bits128(uint128_t *number) {
    uint32_t result = 0;
    if (UPPER_P(number)) {
        result = 64;
        uint64_t up = UPPER_P(number);
        while (up) {
            up >>= 1;
            result++;
        }
    } else {
        uint64_t low = LOWER_P(number);
        while (low) {
            low >>= 1;
            result++;
        }
    }
    return result;
}

static bool gte128(uint128_t *number1, uint128_t *number2) {
    return gt128(number1, number2) || equal128(number1, number2);
}

static void mul128(uint128_t *number1, uint128_t *number2, uint128_t *target) {
    uint64_t top[4] = {UPPER_P(number1) >> 32,
                       UPPER_P(number1) & 0xffffffff,
                       LOWER_P(number1) >> 32,
                       LOWER_P(number1) & 0xffffffff};
    uint64_t bottom[4] = {UPPER_P(number2) >> 32,
                          UPPER_P(number2) & 0xffffffff,
                          LOWER_P(number2) >> 32,
                          LOWER_P(number2) & 0xffffffff};
    uint64_t products[4][4];
    uint128_t tmp, tmp2;

    for (int y = 3; y > -1; y--) {
        for (int x = 3; x > -1; x--) {
            products[3 - x][y] = top[x] * bottom[y];
        }
    }

    uint64_t fourth32 = products[0][3] & 0xffffffff;
    uint64_t third32 = (products[0][2] & 0xffffffff) + (products[0][3] >> 32);
    uint64_t second32 = (products[0][1] & 0xffffffff) + (products[0][2] >> 32);
    uint64_t first32 = (products[0][0] & 0xffffffff) + (products[0][1] >> 32);

    third32 += products[1][3] & 0xffffffff;
    second32 += (products[1][2] & 0xffffffff) + (products[1][3] >> 32);
    first32 += (products[1][1] & 0xffffffff) + (products[1][2] >> 32);

    second32 += products[2][3] & 0xffffffff;
    first32 += (products[2][2] & 0xffffffff) + (products[2][3] >> 32);

    first32 += products[3][3] & 0xffffffff;

    UPPER(tmp) = first32 << 32;
    LOWER(tmp) = 0;
    UPPER(tmp2) = third32 >> 32;
    LOWER(tmp2) = third32 << 32;
    add128(&tmp, &tmp2, target);
    UPPER(tmp) = second32;
    LOWER(tmp) = 0;
    add128(&tmp, target, &tmp2);
    UPPER(tmp) = 0;
    LOWER(tmp) = fourth32;
    add128(&tmp, &tmp2, target);
}

static void divmod128(uint128_t *l, uint128_t *r, uint128_t *retDiv, uint128_t *retMod) {
    uint128_t copyd, adder, resDiv, resMod;
    uint128_t one;
    UPPER(one) = 0;
    LOWER(one) = 1;
    uint32_t diffBits = bits128(l) - bits128(r);
    clear128(&resDiv);
    copy128(&resMod, l);
    if (gt128(r, l)) {
        copy128(retMod, l);
        clear128(retDiv);
    } else {
        shiftl128(r, diffBits, &copyd);
        shiftl128(&one, diffBits, &adder);
        if (gt128(&copyd, &resMod)) {
            shiftr128(&copyd, 1, &copyd);
            shiftr128(&adder, 1, &adder);
        }
        while (gte128(&resMod, r)) {
            if (gte128(&resMod, &copyd)) {
                minus128(&resMod, &copyd, &resMod);
                or128(&resDiv, &adder, &resDiv);
            }
            shiftr128(&copyd, 1, &copyd);
            shiftr128(&adder, 1, &adder);
        }
        copy128(retDiv, &resDiv);
        copy128(retMod, &resMod);
    }
}

static bool tostring128(uint128_t *number, uint32_t baseParam, char *out, uint32_t outLength) {
    uint128_t rDiv;
    uint128_t rMod;
    uint128_t base;
    copy128(&rDiv, number);
    clear128(&rMod);
    clear128(&base);
    LOWER(base) = baseParam;
    uint32_t offset = 0;
    if ((baseParam < 2) || (baseParam > 16)) {
        return false;
    }
    do {
        if (offset > (outLength - 1)) {
            return false;
        }
        divmod128(&rDiv, &base, &rDiv, &rMod);
        out[offset++] = HEXDIGITS[(uint8_t) LOWER(rMod)];
    } while (!zero128(&rDiv));
    out[offset] = '\0';
    reverseString(out, offset);
    return true;
}
#endif
