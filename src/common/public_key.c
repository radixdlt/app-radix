#include "public_key.h"

bool public_key_equals(public_key_t *lhs, public_key_t *rhs) {
    for (int i = 0; i < PUBLIC_KEY_COMPRESSED_LEN; ++i) {
        if (lhs->compressed[i] != rhs->compressed[i]) {
            return false;
        }
    }
    return true;
}