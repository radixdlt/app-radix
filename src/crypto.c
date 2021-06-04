/*****************************************************************************
 *   Ledger App Radix.
 *   (c) 2020 Ledger SAS.
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
 *****************************************************************************/

#include <stdint.h>   // uint*_t
#include <string.h>   // memset, explicit_bzero
#include <stdbool.h>  // bool

#include "crypto.h"
#include "sw.h"

#include "globals.h"

#pragma GCC diagnostic ignored "-Wformat"  // snprintf

int crypto_derive_private_key(cx_ecfp_private_key_t *private_key,
                              uint8_t chain_code[static CHAIN_CODE_LEN],
                              const uint32_t *bip32_path,
                              uint8_t bip32_path_len) {
    uint8_t raw_private_key[PRIVATE_KEY_LEN] = {0};

    BEGIN_TRY {
        TRY {
            // derive the seed with bip32_path
            os_perso_derive_node_bip32(CX_CURVE_256K1,
                                       bip32_path,
                                       bip32_path_len,
                                       raw_private_key,
                                       chain_code);
            // new private_key from raw
            cx_ecfp_init_private_key(CX_CURVE_256K1,
                                     raw_private_key,
                                     sizeof(raw_private_key),
                                     private_key);
        }
        CATCH_OTHER(e) {
            THROW(e);
        }
        FINALLY {
            explicit_bzero(&raw_private_key, sizeof(raw_private_key));
        }
    }
    END_TRY;

    return 0;
}

int crypto_init_public_key(cx_ecfp_private_key_t *private_key,
                           cx_ecfp_public_key_t *public_key,
                           uint8_t raw_public_key[static PUBLIC_KEY_UNCOMPRESSEED_LEN]) {
    // generate corresponding public key
    cx_ecfp_generate_pair(CX_CURVE_256K1,
                          public_key,
                          private_key,
                          1  // KEEP private_key TRUE
    );

    memmove(raw_public_key,
            public_key->W + 1,  // `1` is length of PUBKEY_FLAG_KEY
            PUBLIC_KEY_UNCOMPRESSEED_LEN);

    return 0;
}

bool crypto_init_public_key_from_raw_uncompressed(
    uint8_t raw_uncompressed_public_key[static PUBLIC_KEY_POINT_LEN],
    cx_ecfp_public_key_t *public_key) {
    if (cx_ecfp_init_public_key(CX_CURVE_SECP256K1,
                                raw_uncompressed_public_key,
                                PUBLIC_KEY_POINT_LEN,
                                public_key) != PUBLIC_KEY_POINT_LEN) {
        PRINTF("Invalid public key");
        THROW(INVALID_PARAMETER);
    }
    return true;
}

bool crypto_compress_public_key(cx_ecfp_public_key_t *public_key,
                                uint8_t raw_public_key[static PUBLIC_KEY_COMPRESSED_LEN]) {
    // An uncompressed key has 0x04 + X (32 bytes) + Y (32 bytes).
    if (public_key->W_len != (PUBLIC_KEY_POINT_LEN) ||
        public_key->W[0] != PUBKEY_FLAG_KEY_IS_UNCOMPRESSED) {
        PRINTF(
            "Inputted public key is incorrect, either incorrect length or first byte is not "
            "PUBKEY_FLAG_KEY_IS_UNCOMPRESSED "
            "as expected.\n");
        THROW(INVALID_PARAMETER);
    }

    // check if Y is even or odd. Assuming big-endian, just check the last byte.
    size_t len = 1;  // `1` iis length of PUBKEY_FLAG_KEY
    if (public_key->W[PUBLIC_KEY_UNCOMPRESSEED_LEN] % 2 == 0) {
        // Even
        memset(raw_public_key, PUBKEY_FLAG_KEY_IS_COMPRESSED_Y_IS_EVEN, len);
    } else {
        // Odd
        memset(raw_public_key, PUBKEY_FLAG_KEY_IS_COMPRESSED_Y_IS_ODD, len);
    }

    memmove(raw_public_key + len, public_key->W + len, PUBLIC_KEY_UNCOMPRESSEED_LEN);

    return true;
}

int crypto_sign_message() {
    cx_ecfp_private_key_t private_key = {0};
    uint8_t chain_code[CHAIN_CODE_LEN] = {0};
    uint32_t info = 0;
    int sig_len = 0;

    // derive private key according to BIP32 path
    crypto_derive_private_key(&private_key,
                              chain_code,
                              G_context.bip32_path,
                              G_context.bip32_path_len);

    BEGIN_TRY {
        TRY {
            sig_len = cx_ecdsa_sign(&private_key,
                                    CX_RND_RFC6979 | CX_LAST,
                                    CX_SHA256,
                                    G_context.sig_info.m_hash,
                                    sizeof(G_context.sig_info.m_hash),
                                    G_context.sig_info.signature,
                                    sizeof(G_context.sig_info.signature),
                                    &info);
            PRINTF("Signature: %.*h\n", sig_len, G_context.sig_info.signature);
        }
        CATCH_OTHER(e) {
            THROW(e);
        }
        FINALLY {
            explicit_bzero(&private_key, sizeof(private_key));
        }
    }
    END_TRY;

    if (sig_len < 0) {
        return -1;
    }

    G_context.sig_info.signature_len = sig_len;
    G_context.sig_info.v = (uint8_t) (info & CX_ECCINFO_PARITY_ODD);

    return 0;
}

bool crypto_ecdh(void) {
    cx_ecfp_private_key_t private_key = {0};
    uint8_t chain_code[CHAIN_CODE_LEN] = {0};
    int sharedkey_len = 0;

    // derive private key according to BIP32 path
    crypto_derive_private_key(&private_key,
                              chain_code,
                              G_context.bip32_path,
                              G_context.bip32_path_len);

    BEGIN_TRY {
        TRY {
            sharedkey_len = cx_ecdh(&private_key,
                                    CX_ECDH_POINT,  // or `CX_ECDH_X`
                                    G_context.ecdh_info.other_party_public_key.W,
                                    G_context.ecdh_info.other_party_public_key.W_len,
                                    G_context.ecdh_info.shared_pubkey_point,
                                    sizeof(G_context.ecdh_info.shared_pubkey_point));
            PRINTF("Derived shared key with length: %d\n", sharedkey_len);
        }
        CATCH_OTHER(e) {
            THROW(e);
        }
        FINALLY {
            explicit_bzero(&private_key, sizeof(private_key));
        }
    }
    END_TRY;

    if (sharedkey_len < 0) {
        return false;
    }

    return true;
}