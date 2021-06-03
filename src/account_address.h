#pragma once

#include <stdint.h>   // uint*_t
#include <stddef.h>   // size_t
#include <stdbool.h>  // bool

#include "constants.h"  // PUBLIC_KEY_COMPRESSEED_LEN

#define ACCOUNT_ADDRESS_VERSION_BYTE        0x04
#define ACCOUNT_ADDRESS_VERSION_DATA_LENGTH 1  // one byte

#define ACCOUNT_ADDRESS_HRP_LENGTH  3
#define ACCOUNT_ADDRESS_HRP_MAINNET "rdx"
#define ACCOUNT_ADDRESS_HRP_BETANET "brx"

#define ACCOUNT_ADDRESS_LEN 65

/**
 * Convert public key to address. If successful, sets `out_len` to actual length.
 *
 * address = bech32(raw_public_key, ACCOUNT_ADDRESS_VERSION_BYTE)
 *
 * @param[in]  raw_public_key
 *   Pointer to byte buffer with public key.
 *   The public key is represented as 33 bytes on compressed format
 * @param[out] out
 *   Pointer to output byte buffer for address.
 * @param[in,out]  out_len
 *   Pointer to lenght of output byte buffer, will be set to actual lenght.
 *
 * @return true if success, false otherwise.
 *
 */
bool account_address_from_pubkey(const uint8_t raw_public_key[static PUBLIC_KEY_COMPRESSEED_LEN],
                                 char *out,
                                 size_t *out_len);