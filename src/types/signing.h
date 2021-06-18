#pragma once

#include <stdint.h>  // uint8_t
#include "hasher.h"
#include "signature.h"
#include "derived_public_key.h"

typedef struct {
    derived_public_key_t my_derived_public_key;  /// Public key and BIP32 path used to sign.
    // uint8_t digest[HASH_LEN];                    /// message hash digest
    hasher_t hasher;

    signature_t signature;  /// Produced ECDSA signature.
} signing_t;
