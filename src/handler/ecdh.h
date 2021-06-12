#pragma once

#include <stddef.h>   // size_t
#include <stdbool.h>  // bool
#include <stdint.h>   // uint*_t

#include "../state.h"
#include "../common/buffer.h"

/**
 * Handler for ECDH (Diffie-Hellman) key exchange command. If successfully parse BIP32 path,
 * public key of other party, we derive a shared public key and send APDU response.
 *
 * @see G_context.bip32_path, G_context.echd_info.raw_uncompressed_public_key and
 *      G_context.echd_info.chain_code.
 *
 * @param[in,out] cdata
 *   Command data with BIP32 path.
 * @param[in]     display
 *   Whether to display shared key on screen or not.
 *
 * @return zero or positive integer if success, negative integer otherwise.
 *
 */
int handler_ecdh(buffer_t *cdata, bool display);
