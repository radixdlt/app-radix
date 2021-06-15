#pragma once

#include "../constants.h"
#include <stdint.h>  // uint8_t
#include "signature.h"
#include "derived_public_key.h"

typedef struct {
    derived_public_key_t my_derived_public_key;  /// Public key and BIP32 path used to sign.
    uint8_t digest[HASH_LEN];                    /// message hash digest

    signature_t signature;  /// Produced ECDSA signature.
} signing_t;
