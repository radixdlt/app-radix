#pragma once

#include "os.h"

/**
 * Helper to send APDU response with public key and chain code.
 *
 * response = PUBLIC_KEY_UNCOMPRESSEED_LEN (1) ||
 *            G_context.pk_info.public_key (PUBLIC_KEY_UNCOMPRESSEED_LEN) ||
 *            CHAIN_CODE_LEN (1) ||
 *            G_context.pk_info.chain_code (CHAIN_CODE_LEN)
 *
 * @return zero or positive integer if success, -1 otherwise.
 *
 */
int helper_send_response_pubkey(void);

/**
 * Helper to send APDU response with signature and v (parity of
 * y-coordinate of R).
 *
 * response = G_context.tx_info.signature_len (1) ||
 *            G_context.tx_info.signature (G_context.tx_info.signature_len) ||
 *            G_context.tx_info.v (1)
 *
 * @return zero or positive integer if success, -1 otherwise.
 *
 */
int helper_send_response_signature(bool include_hash_in_response, const uint8_t *hash);

/**
 * Helper to send APDU response with shared ECDH key.
 *
 * response = SHARED_KEY_LEN (1) ||
 *            G_context.ecdh_info.shared_pubkey_point (SHARED_KEY_LEN)
 *
 * @return zero or positive integer if success, -1 otherwise.
 *
 */
int helper_send_response_sharedkey(void);