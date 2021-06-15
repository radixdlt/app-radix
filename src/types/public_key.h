#pragma once

#include <stdint.h>  // uint8_t
#include <stdbool.h>
#include "../constants.h"  // PUBLIC_KEY_COMPRESSED_LEN

typedef struct {
    uint8_t compressed[PUBLIC_KEY_COMPRESSED_LEN];
} public_key_t;

bool public_key_equals(public_key_t *lhs, public_key_t *rhs);