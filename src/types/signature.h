#pragma once

#include <stdint.h>  // uint8_t
#include "../constants.h"

typedef struct {
    uint8_t der[MAX_DER_SIG_LEN];  /// transaction signature encoded in DER
    uint8_t der_len;               /// length of transaction signature
    uint8_t v;                     /// parity of y-coordinate of R in ECDSA signature
} signature_t;
