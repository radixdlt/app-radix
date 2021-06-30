#include "prepared_unstake.h"

#include "../../sw.h"
#include "../../bridge.h"

bool parse_prepared_unstake(buffer_t *buffer,
                            parse_prepared_unstake_outcome_t *outcome,
                            prepared_unstake_t *prepared_unstake) {
    // Parse field 'reserved'
    if (!buffer_read_u8(buffer, &prepared_unstake->reserved)) {
        PRINTF("Failed to parse 'reserved' in substate 'PREPARED_UNSTAKE'.\n");
        outcome->outcome_type = PARSE_PREPARED_UNSTAKE_FAILURE_PARSE_RESERVED;
        return false;
    }

    // Parse field 'validator'
    if (!buffer_move_fill_target(buffer,
                                 (uint8_t *) &prepared_unstake->validator.public_key.compressed,
                                 PUBLIC_KEY_COMPRESSED_LEN)) {
        PRINTF("Failed to parse 'validator' in substate 'PREPARED_UNSTAKE'.\n");
        outcome->outcome_type = PARSE_PREPARED_UNSTAKE_FAILURE_PARSE_VALIDATOR;
        return false;
    }
    prepared_unstake->validator.address_type = RE_ADDRESS_PUBLIC_KEY;

    // Parse field 'owner'
    if (!parse_re_address(buffer, &outcome->owner_parse_failure_reason, &prepared_unstake->owner)) {
        PRINTF("Failed to parse 'owner' in substate 'PREPARED_UNSTAKE'.\n");
        outcome->outcome_type = PARSE_PREPARED_UNSTAKE_FAILURE_PARSE_OWNER;
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
        case PARSE_PREPARED_UNSTAKE_FAILURE_PARSE_RESERVED:
            return ERR_CMD_SIGN_TX_PREPARED_UNSTAKE_PARSE_RESERVED_FAILURE;
        case PARSE_PREPARED_UNSTAKE_FAILURE_PARSE_VALIDATOR:
            return ERR_CMD_SIGN_TX_PREPARED_UNSTAKE_PARSE_VALIDATOR_FAILURE;
        case PARSE_PREPARED_UNSTAKE_FAILURE_PARSE_OWNER:
            return ERR_CMD_SIGN_TX_PREPARED_UNSTAKE_PARSE_OWNER_FAILURE;
        case PARSE_PREPARED_UNSTAKE_FAILURE_PARSE_AMOUNT:
            return ERR_CMD_SIGN_TX_PREPARED_UNSTAKE_PARSE_AMOUNT_FAILURE;
    }

    return ERR_BAD_STATE;  // should never happen
}
