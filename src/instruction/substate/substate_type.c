#include "substate_type.h"

bool is_re_substate_type_known(uint8_t raw) {
    return raw <= RE_SUBSTATE_TYPE_LAST_KNOWN;
}

bool is_re_substate_type_supported(uint8_t raw) {
    switch (raw) {
        case SUBSTATE_TYPE_TOKENS:            // Token transfer
        case SUBSTATE_TYPE_PREPARED_STAKE:    // Stake tokens
        case SUBSTATE_TYPE_STAKE_SHARE:       // Partial unstake tokens
        case SUBSTATE_TYPE_PREPARED_UNSTAKE:  // Unstake tokens
            return true;
    }
    return false;
}
