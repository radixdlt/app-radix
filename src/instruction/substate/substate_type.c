#include "substate_type.h"
#include "os.h"

bool is_re_substate_type_known(int raw) {
    return raw > 0 && raw <= RE_SUBSTATE_TYPE_LAST_KNOWN;
}

bool is_re_substate_type_supported(int raw) {
    switch (raw) {
        case SUBSTATE_TYPE_TOKENS:            // Token transfer
        case SUBSTATE_TYPE_PREPARED_STAKE:    // Stake tokens
        case SUBSTATE_TYPE_STAKE_SHARE:       // Partial unstake tokens
        case SUBSTATE_TYPE_PREPARED_UNSTAKE:  // Unstake tokens
            return true;
    }
    return false;
}

void print_re_substate_type(re_substate_type_e substate_type) {
    PRINTF("Substate type: ");
    switch (substate_type) {
        case SUBSTATE_TYPE_TOKENS:
            PRINTF("'TOKENS'");
            break;
        case SUBSTATE_TYPE_PREPARED_STAKE:
            PRINTF("'PREPARED_STAKE'");
            break;
        case SUBSTATE_TYPE_STAKE_SHARE:
            PRINTF("'STAKE_SHARE'");
            break;
        case SUBSTATE_TYPE_PREPARED_UNSTAKE:
            PRINTF("'PREPARED_UNSTAKE'");
            break;
        default:
            PRINTF("UNKNOWN substate type: %d", substate_type);
            break;
    }
    PRINTF("\n");
}
