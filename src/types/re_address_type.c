#include "re_address_type.h"

bool is_re_address_type_known(int raw) {
    return raw >= RE_ADDRESS_NATIVE_TOKEN && raw <= RE_ADDRESS_PUBLIC_KEY;
}

bool is_re_address_type_supported(int raw) {
    switch (raw) {
        case RE_ADDRESS_NATIVE_TOKEN:
        case RE_ADDRESS_HASHED_KEY_NONCE:
        case RE_ADDRESS_PUBLIC_KEY:
            return true;
    }
    return false;
}