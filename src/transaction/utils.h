#pragma once

#include <stdint.h>   // uint*_t
#include <stdbool.h>  // bool

#include "types.h"

/**
 * Check if message is encoded using ASCII characters.
 *
 * @param[in] message
 *   Pointer to input byte buffer.
 * @param[in] message_len
 *   Lenght of input byte buffer.
 *
 * @return true if success, false otherwise.
 *
 */
bool transaction_utils_check_encoding(const uint8_t *message, uint64_t message_len);

/**
 * Format message as string.
 *
 * @param[in]  message
 *   Pointer to input byte buffer.
 * @param[in]  message_len
 *   Lenght of input byte buffer.
 * @param[out] dst
 *   Pointer to output string.
 * @param[in]  dst_len
 *   Lenght of output string.
 *
 * @return true if success, false otherwise.
 *
 */
bool transaction_utils_format_memo(const uint8_t *message,
                                   uint64_t message_len,
                                   char *dst,
                                   uint64_t dst_len);
