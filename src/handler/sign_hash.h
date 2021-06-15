#pragma once

#include <stdint.h>   // uint*_t
#include <stdbool.h>  // bool

#include "../types/buffer.h"

/**
 * Handler for SIGN_HASH command. If successfully parse BIP32 path
 * and read hash, sign the hash and send APDU response.
 *
 * @see G_context.bip32_path, G_context.tx_hash_info.hash,
 * G_context.tx_hash_info.signature and G_context.tx_hash_info.v.
 *
 * @param[in,out] cdata
 *   Command data with BIP32 path and hash of tx data.
 *
 * @return zero or positive integer if success, negative integer otherwise.
 *
 */
int handler_sign_hash(buffer_t *cdata);
