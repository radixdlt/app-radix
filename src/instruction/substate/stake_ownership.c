#include "stake_ownership.h"

#include "../../sw.h"
#include "../../bridge.h"

bool parse_stake_ownership(buffer_t *buffer,
                           parse_stake_ownership_outcome_t *outcome,
                           stake_ownership_t *stake_ownership) {
    // Parse field 'reserved'
    if (!buffer_read_u8(buffer, &stake_ownership->reserved)) {
        PRINTF("Failed to parse 'reserved' in substate 'STAKE_OWNERSHIP'.\n");
        outcome->outcome_type = PARSE_STAKE_OWNERSHIP_FAILURE_PARSE_RESERVED;
        return false;
    }

    // Parse field 'validator'
    if (!buffer_move_fill_target(buffer,
                                 (uint8_t *) &stake_ownership->validator.public_key.compressed,
                                 PUBLIC_KEY_COMPRESSED_LEN)) {
        PRINTF("Failed to parse 'validator' in substate 'STAKE_OWNERSHIP'.\n");
        outcome->outcome_type = PARSE_STAKE_OWNERSHIP_FAILURE_PARSE_VALIDATOR;
        return false;
    }
    stake_ownership->validator.address_type = RE_ADDRESS_PUBLIC_KEY;

    // Parse field 'owner'
    if (!parse_re_address(buffer, &outcome->owner_parse_failure_reason, &stake_ownership->owner)) {
        PRINTF("Failed to parse 'owner' in substate 'STAKE_OWNERSHIP'.\n");
        outcome->outcome_type = PARSE_STAKE_OWNERSHIP_FAILURE_PARSE_OWNER;
        return false;
    }

    // Parse field 'amount'
    if (!uint256_from_buffer(buffer, &stake_ownership->amount)) {
        PRINTF("Failed to parse 'amount' in substate 'STAKE_OWNERSHIP'.\n");
        outcome->outcome_type = PARSE_STAKE_OWNERSHIP_FAILURE_PARSE_AMOUNT;
        return false;
    }

    outcome->outcome_type = PARSE_STAKE_OWNERSHIP_OK;

    return true;
}

uint16_t status_word_for_failed_to_parse_stake_ownership(
    parse_stake_ownership_outcome_e failure_reason) {
    switch (failure_reason) {
        case PARSE_STAKE_OWNERSHIP_OK:
            return SW_OK;
        case PARSE_STAKE_OWNERSHIP_FAILURE_PARSE_RESERVED:
            return ERR_CMD_SIGN_TX_STAKE_OWNERSHIP_PARSE_RESERVED_FAILURE;
        case PARSE_STAKE_OWNERSHIP_FAILURE_PARSE_VALIDATOR:
            return ERR_CMD_SIGN_TX_STAKE_OWNERSHIP_PARSE_VALIDATOR_FAILURE;
        case PARSE_STAKE_OWNERSHIP_FAILURE_PARSE_OWNER:
            return ERR_CMD_SIGN_TX_STAKE_OWNERSHIP_PARSE_OWNER_FAILURE;
        case PARSE_STAKE_OWNERSHIP_FAILURE_PARSE_AMOUNT:
            return ERR_CMD_SIGN_TX_STAKE_OWNERSHIP_PARSE_AMOUNT_FAILURE;
    }

    return ERR_BAD_STATE;  // should never happen
}
