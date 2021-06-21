#pragma once

#include <stdbool.h>

typedef enum {
    // RE_ADDRESS_SYSTEM = 0x00,    // UNSUPPORTED
    RE_ADDRESS_NATIVE_TOKEN = 0x01,
    RE_ADDRESS_HASHED_KEY_NONCE = 0x03,
    RE_ADDRESS_PUBLIC_KEY = 0x04,
} re_address_type_e;

bool is_re_address_type_known(int raw);

bool is_re_address_type_supported(int raw);
