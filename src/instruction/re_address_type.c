#include "re_address_type.h"
#include "os.h"

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

void print_re_address_type(re_address_type_e address_type) {
    PRINTF("RE address type: ");
    switch (address_type) {
        case RE_ADDRESS_NATIVE_TOKEN:
            PRINTF("'NATIVE_TOKEN'");
            break;
        case RE_ADDRESS_HASHED_KEY_NONCE:
            PRINTF("'HASHED_KEY_NONCE'");
            break;
        case RE_ADDRESS_PUBLIC_KEY:
            PRINTF("'PUBLIC_KEY'");
            break;
    }
    PRINTF("\n");
}