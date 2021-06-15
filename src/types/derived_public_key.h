#pragma once

#include "bip32_path.h"
#include "re_address.h"

typedef struct {
    bip32_path_t bip32_path;
    re_address_t address;
} derived_public_key_t;