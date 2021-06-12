
#pragma once

#include <stdint.h>  // uint*_t
#include <stdbool.h>

#include "os.h"
#include "cx.h"

#include "constants.h"
#include "common/public_key.h"

/**
 * Derive private key given BIP32 path.
 *
 * @param[out] private_key
 *   Pointer to private key.
 * @param[out] chain_code
 *   Pointer to 32 bytes array for chain code.
 * @param[in]  bip32_path
 *   Pointer to buffer with BIP32 path.
 * @param[in]  bip32_path_len
 *   Number of path in BIP32 path.
 *
 * @return `true` iff success, otherwise `false.
 *
 * @throw INVALID_PARAMETER
 *
 */
bool crypto_derive_private_key(cx_ecfp_private_key_t *private_key,
                               uint8_t chain_code[static CHAIN_CODE_LEN],
                               const uint32_t *bip32_path,
                               uint8_t bip32_path_len);

/**
 * Initialize public key given private key.
 *
 * @param[in]  private_key
 *   Pointer to private key.
 * @param[out] public_key
 *   Pointer to public key.
 * @param[out] raw_public_key
 *   Pointer to raw public key.
 *
 * @return `true` iff success, otherwise `false.
 *
 * @throw INVALID_PARAMETER
 *
 */
bool crypto_init_public_key(cx_ecfp_private_key_t *private_key,
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

/**
 * Sign message hash in global context.
 *
 * @see G_context.bip32_path, G_context.tx_info.m_hash,
 * G_context.tx_info.signature.
 *
 * @return `true` iff success, otherwise `false.
 *
 * @throw INVALID_PARAMETER
 *
 */
bool crypto_sign_message(void);

/**
 * @brief Performs ECDH with provided public key.
 *
 * Performs an ECDH key echange with key at BIP32 path and provided publickey point of some other
 * party.
 *
 *  * @see G_context.bip32_path, ecdh_info.other_party_public_key,
 * ecdh_info.shared_pubkey_point.
 *
 * @return `true` iff success, otherwise `false`.
 */
bool crypto_ecdh(void);

/**
 * @brief Updates hasher.
 *
 * Updates hasher and "finalizes" it if `should_finalize` is true.
 * Finalizing it performs sha256 again, meaining that we do SHA256(SHA256(buffer)).
 *
 * @param in
 * @param in_len
 * @param should_finalize
 * @param hasher
 * @param out
 * @param out_len
 * @return true iff successful.
 * @return false iff failure
 */
bool update_hash(cx_sha256_t *hasher,
                 const uint8_t *in,
                 const size_t in_len,
                 bool should_finalize,
                 uint8_t *out,
                 const size_t out_len);