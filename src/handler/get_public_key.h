#pragma once

#include <stddef.h>   // size_t
#include <stdbool.h>  // bool
#include <stdint.h>   // uint*_t

#include "../state.h"
#include "../types/buffer.h"

/**
 * Handler for GET_PUBLIC_KEY command. If successfully parse BIP32 path,
 * derive public key/chain code and send APDU response.
 *
 * @see G_context.bip32_path, G_context.pk_info.raw_uncompressed_public_key and
 *      G_context.pk_info.chain_code.
 *
 * @param[in,out] cdata
 *   Command data with BIP32 path.
 * @param[in] display
 *   Whether to display address on screen or not.
 * @param[in] address_verification_only
 *   Whether to only display address on screen or not (skipping BIP32 path).
 *
 * @return zero or positive integer if success, negative integer otherwise.
 *
 */
int handler_get_public_key(buffer_t *cdata, bool display, bool address_verification_only);
