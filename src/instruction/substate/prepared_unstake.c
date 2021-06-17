#include "prepared_unstake.h"

#include "../../sw.h"
#include "../../bridge.h"

bool parse_prepared_unstake(buffer_t *buffer,
                            parse_prepared_unstake_outcome_t *outcome,
                            prepared_unstake_t *prepared_unstake) {
    // Parse field 'delegate'
    if (!buffer_move_fill_target(buffer,
                                 (uint8_t *) &prepared_unstake->delegate.public_key.compressed,
                                 PUBLIC_KEY_COMPRESSED_LEN)) {
        PRINTF("Failed to parse 'delegate' in substate 'PREPARED_UNSTAKE'.\n");
        outcome->outcome_type = PARSE_PREPARED_UNSTAKE_FAILURE_PARSE_DELEGATE;
        return false;
    }
    prepared_unstake->delegate.address_type = RE_ADDRESS_PUBLIC_KEY;

    // Parse field 'owner'
    parse_address_failure_reason_e parse_owner_failure;
    if (!parse_re_address(buffer, &parse_owner_failure, &prepared_unstake->owner)) {
        PRINTF("Failed to parse 'owner' in substate 'PREPARED_UNSTAKE'.\n");
        outcome->outcome_type = PARSE_PREPARED_UNSTAKE_FAILURE_PARSE_OWNER;
        outcome->owner_parse_failure_reason = parse_owner_failure;
        return false;
    }

    // Parse field 'amount'
    if (!uint256_from_buffer(buffer, &prepared_unstake->amount)) {
        PRINTF("Failed to parse 'amount' in substate 'PREPARED_UNSTAKE'.\n");
        outcome->outcome_type = PARSE_PREPARED_UNSTAKE_FAILURE_PARSE_AMOUNT;
        return false;
    }

    outcome->outcome_type = PARSE_PREPARED_UNSTAKE_OK;

    return true;
}

uint16_t status_word_for_failed_to_parse_prepared_unstake(
    parse_prepared_unstake_outcome_e failure_reason) {
    switch (failure_reason) {
        case PARSE_PREPARED_UNSTAKE_OK:
            return SW_OK;
        case PARSE_PREPARED_UNSTAKE_FAILURE_PARSE_DELEGATE:
            return ERR_CMD_SIGN_TX_PREPARED_UNSTAKE_PARSE_DELEGATE_FAILURE;
        case PARSE_PREPARED_UNSTAKE_FAILURE_PARSE_OWNER:
            return ERR_CMD_SIGN_TX_PREPARED_UNSTAKE_PARSE_OWNER_FAILURE;
        case PARSE_PREPARED_UNSTAKE_FAILURE_PARSE_AMOUNT:
            return ERR_CMD_SIGN_TX_PREPARED_UNSTAKE_PARSE_AMOUNT_FAILURE;
    }

    return ERR_BAD_STATE;  // should never happen
}
