#include "prepared_stake.h"
#include "../../sw.h"

bool parse_prepared_stake(buffer_t *buffer,
                          parse_prepared_stake_outcome_t *outcome,
                          prepared_stake_t *prepared_stake) {
    // Parse field 'owner'
    parse_address_failure_reason_e parse_owner_failure;
    if (!parse_re_address(buffer, &parse_owner_failure, &prepared_stake->owner)) {
        PRINTF("Failed to parse 'owner' in substate 'PREPARED_TOKENS'.\n");
        outcome->outcome_type = PARSE_PREPARED_STAKE_FAILURE_PARSE_OWNER;
        outcome->parse_owner_failure = parse_owner_failure;
        return false;
    }

    // Parse field 'delegate'.
    if (!buffer_move_fill_target(buffer,
                                 (uint8_t *) &prepared_stake->delegate.public_key.compressed,
                                 PUBLIC_KEY_COMPRESSED_LEN)) {
        PRINTF("Failed to parse 'delegate' in substate 'PREPARED_TOKENS'.\n");
        outcome->outcome_type = PARSE_PREPARED_STAKE_FAILURE_PARSE_DELEGATE;
        return false;
    }
    prepared_stake->delegate.address_type = RE_ADDRESS_PUBLIC_KEY;

    // Parse field 'amount'
    if (!uint256_from_buffer(buffer, &prepared_stake->amount)) {
        PRINTF("Failed to parse 'amount' in substate 'PREPARED_TOKENS'.\n");
        outcome->outcome_type = PARSE_PREPARED_STAKE_FAILURE_PARSE_AMOUNT;
        return false;
    }

    outcome->outcome_type = PARSE_PREPARED_STAKE_OK;

    return true;
}

uint16_t status_word_for_failed_to_parse_prepared_stake(
    parse_prepared_stake_outcome_e failure_reason) {
    switch (failure_reason) {
        case PARSE_PREPARED_STAKE_OK:
            return SW_OK;
        case PARSE_PREPARED_STAKE_FAILURE_PARSE_OWNER:
            return ERR_CMD_SIGN_TX_PREPARED_STAKE_PARSE_OWNER_FAILURE;
        case PARSE_PREPARED_STAKE_FAILURE_PARSE_DELEGATE:
            return ERR_CMD_SIGN_TX_PREPARED_STAKE_PARSE_DELEGATE_FAILURE;
        case PARSE_PREPARED_STAKE_FAILURE_PARSE_AMOUNT:
            return ERR_CMD_SIGN_TX_PREPARED_STAKE_PARSE_AMOUNT_FAILURE;
    }
}

void print_parse_prepared_stake_outcome(parse_prepared_stake_outcome_t *outcome) {
    PRINTF("parse prepared stake outcome: ");
    switch (outcome->outcome_type) {
        case PARSE_PREPARED_STAKE_OK:
            PRINTF("'OK'");
            break;
        case PARSE_PREPARED_STAKE_FAILURE_PARSE_DELEGATE:
            PRINTF("'FAILURE_PARSE_DELEGATE'");
            break;
        case PARSE_PREPARED_STAKE_FAILURE_PARSE_OWNER:
            PRINTF("'FAILURE_PARSE_OWNER' - printing reason:\n");
            print_parse_address_failure_reason(outcome->parse_owner_failure);
            break;
        case PARSE_PREPARED_STAKE_FAILURE_PARSE_AMOUNT:
            PRINTF("'FAILURE_PARSE_AMOUNT'");
            break;
    }
    PRINTF("\n");
}