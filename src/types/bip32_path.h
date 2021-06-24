#pragma once

#include <stddef.h>   // size_t
#include <stdint.h>   // uint*_t
#include <stdbool.h>  // bool

/**
 * Maximum length of BIP32 path allowed.
 */
#define MAX_BIP32_PATH 10

typedef struct {
    uint32_t path[MAX_BIP32_PATH];
    uint8_t path_len;
} bip32_path_t;

/**
 * Read BIP32 path from byte buffer.
 *
 * @param[in]  in
 *   Pointer to input byte buffer.
 * @param[in]  in_len
 *   Length of input byte buffer.
 * @param[out] out
 *   Pointer to resulting struct.
 *
 * @return true if success, false otherwise.
 *
 */
bool bip32_path_read(const uint8_t *in, size_t in_len, bip32_path_t *out);

/**
 * Format BIP32 path as string.
 *
 * @param[in]  bip32_path
 *  Struct with the bip32 path
 * @param[out] out string
 *   Pointer to output string.
 * @param[in]  out_len
 *   Length of the output string.
 *
 * @return true if success, false otherwise.
 *
 */
bool bip32_path_format(const bip32_path_t *bip32_path, char *out, size_t out_len);
