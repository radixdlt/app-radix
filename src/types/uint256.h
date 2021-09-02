
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

// Taken from: https://github.com/LedgerHQ/app-ethereum/blob/master/src_common/uint256.h
// Adapted from https://github.com/calccrypto/uint256_t

#pragma once

#include <stdint.h>
#include <stdbool.h>

typedef struct uint128_t {
    uint64_t elements[2];
} uint128_t;

typedef struct uint256_t {
    uint128_t elements[2];
} uint256_t;

#define UPPER_P(x) x->elements[0]
#define LOWER_P(x) x->elements[1]
#define UPPER(x)   x.elements[0]
#define LOWER(x)   x.elements[1]

// Prototypes for actually used subset of API's
void readu256BE(uint8_t *buffer, uint256_t *target);
void copy256(uint256_t *target, const uint256_t *number);
void clear256(uint256_t *target);
bool gt256(const uint256_t *number1, const uint256_t *number2);
void add256(const uint256_t *number1, const uint256_t *number2, uint256_t *target);
void minus256(const uint256_t *number1, const uint256_t *number2, uint256_t *target);

// Extension by Alexander Cyon @ Radix DLT
#define UINT256_DEC_STRING_MAX_LENGTH 78
#define UINT256_BYTE_COUNT            32
#include "../types/buffer.h"

/**
 * @brief Parse a \struct uint256_t from \p buffer.
 *
 * @param buffer buffer to read 32 bytes from.
 * @param target target to write to.
 * @return true iff success.
 * @return false iff failure.
 */
bool uint256_from_buffer(buffer_t *buffer, uint256_t *target);

/**
 * @brief Formats a UInt256 as a decimal string and sets the actual len to \p actual_len
 *
 * @param[int] uint256
 * @param[out] out will contain a decimal string
 * @param[in] out_len length of \p out.
 * @param[out] actual_len  the actual length of \p out.
 * @return true If was successful.
 * @return false If failed.
 */
bool to_string_uint256_get_len(const uint256_t *uint256, 
                               char *out, 
                               const size_t out_len, 
                               size_t *actual_len);

/**
 * @brief Formats a UInt256 as a decimal string
 *
 * @param[int] uint256
 * @param[out] out will contain a decimal string
 * @param[in] out_len length of \p out.
 * @return true If was successful.
 * @return false If failed.
 */
bool to_string_uint256(const uint256_t *uint256, char *out, const size_t out_len);

/**
 * @brief Checks if \p target > 0
 *
 * @param target uint256 to compare with zero.
 * @return true iff greater than 0, else false.
 */
bool is_uint256_greater_than_zero(const uint256_t *target);