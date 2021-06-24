
#pragma once

#include <stdint.h>  // uint*_t
#include <stdbool.h>

#include "os.h"
#include "cx.h"

#include "constants.h"
#include "state.h"  // `signing_t`, `bip32_path_t`
#include "types/public_key.h"

/**
 * Derive private key given BIP32 path, outputs resulting chain code.
 *
 * @param[out] private_key
 *   Pointer to private key.
 * @param[out] chain_code
 *   Pointer to 32 bytes array for chain code.
 * @param[in]  bip32_path
 *   Pointer to buffer with BIP32 path.
 *
 * @return `true` iff success, otherwise `false.
 *
 * @throw INVALID_PARAMETER
 *
 */
bool crypto_derive_private_key_and_chain_code(cx_ecfp_private_key_t *private_key,
                                              uint8_t chain_code[static CHAIN_CODE_LEN],
                                              bip32_path_t *bip32_path);

/**
 * Derive private key given BIP32 path, but discards chain code.
 *
 * @param[out] private_key
 *   Pointer to private key.
 * @param[in]  bip32_path
 *   Pointer to buffer with BIP32 path.
 *
 * @return `true` iff success, otherwise `false.
 *
 * @throw INVALID_PARAMETER
 *
 */
bool crypto_derive_private_key(cx_ecfp_private_key_t *private_key, bip32_path_t *bip32_path);

/**
 * Initialize public key given private key.
 *
 * @param[in]  private_key
 *   Pointer to private key.
 * @param[out] public_key
 *   Pointer to public key.
 *
 * @return `true` iff success, otherwise `false.
 *
 * @throw INVALID_PARAMETER
 *
 */
bool crypto_init_public_key(cx_ecfp_private_key_t *private_key, cx_ecfp_public_key_t *public_key);

/**
 * Initialize public key given private key.
 *
 * @param[in]  private_key
 *   Pointer to private key.
 * @param[out] public_key
 *   Pointer to public key.
 * @param[out] raw_public_key
 *  Pointer to a raw bytes buffer to export the public key to.
 *
 * @return `true` iff success, otherwise `false.
 *
 * @throw INVALID_PARAMETER
 *
 */
bool crypto_init_and_export_public_key(cx_ecfp_private_key_t *private_key,
                                       cx_ecfp_public_key_t *public_key,
                                       uint8_t raw_public_key[static PUBLIC_KEY_UNCOMPRESSEED_LEN]);

/**
 * Initialize public key from an uncompressed raw key buffer.
 *
 * @param[in] raw_uncompressed_public_key
 *   Pointer to raw public key on uncompressed format.
 * @param[out] public_key
 *   Pointer to public key.
 *
 * @return `true` iff success, otherwise `false.
 *
 * @throw INVALID_PARAMETER
 *
 */
bool crypto_init_public_key_from_raw_uncompressed(
    uint8_t raw_uncompressed_public_key[static PUBLIC_KEY_POINT_LEN],
    cx_ecfp_public_key_t *public_key);

/**
 * Compresses a public key and outputs to the provided buffer.
 *
 * @param[in] public_key
 *   Pointer to an uncompressed public key.
 * @param[out] raw_public_key
 *   Pointer to raw public key.
 *
 * @return `true` iff success, otherwise `false.
 *
 * @throw INVALID_PARAMETER
 *
 */
bool crypto_compress_public_key_raw(cx_ecfp_public_key_t *public_key,
                                    uint8_t raw_public_key[static PUBLIC_KEY_COMPRESSED_LEN]);
bool crypto_compress_public_key(cx_ecfp_public_key_t *public_key,
                                public_key_t *public_key_compressed);

bool crypto_sign_message(signing_t *signing);

/**
 * @brief Performs ECDH key exchange between your key at \p bip32_path and \p
 * other_party_public_key and put result in \p shared_pubkey_point.
 *
 * @param bip32_path
 * @param other_party_public_key
 * @param shared_pubkey_point
 * @return true
 * @return false
 */
bool crypto_ecdh(bip32_path_t *bip32_path,
                 cx_ecfp_public_key_t *other_party_public_key,
                 uint8_t shared_pubkey_point[static PUBLIC_KEY_POINT_LEN]);

bool sha256_hash_ledger_sdk(cx_sha256_t *hash_context,
                            buffer_t *buffer,
                            bool finalize,  // if `false` then `out` is not used
                            uint8_t *out);