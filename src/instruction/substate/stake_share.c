#include "stake_share.h"
#include "../../sw.h"

bool parse_stake_share(buffer_t *buffer,
                       parse_stake_share_outcome_t *outcome,
                       stake_share_t *stake_share) {
    // Parse field 'publickey'
    if (!buffer_move_fill_target(buffer,
                                 (uint8_t *) &stake_share->public_key.compressed,
                                 PUBLIC_KEY_COMPRESSED_LEN)) {
        PRINTF("Failed to parse 'publickey' in substate 'STAKE_SHARE'.\n");
        outcome->outcome_type = PARSE_STAKE_SHARE_FAILURE_PARSE_PUBLICKEY;
        return false;
    }

    // Parse field 'owner'
    parse_address_failure_reason_e parse_address_failure;
    if (!parse_re_address(buffer, &parse_address_failure, &stake_share->owner)) {
        PRINTF("Failed to parse 'owner' in substate 'STAKE_SHARE'.\n");
        outcome->outcome_type = PARSE_STAKE_SHARE_FAILURE_PARSE_OWNER;
        outcome->owner_parse_failure_reason = parse_address_failure;
        return false;
    }

    // Parse field 'amount'
    if (!uint256_from_buffer(buffer, &stake_share->amount)) {
        PRINTF("Failed to parse 'amount' in substate 'STAKE_SHARE'.\n");
        outcome->outcome_type = PARSE_STAKE_SHARE_FAILURE_PARSE_AMOUNT;
        return false;
    }

    outcome->outcome_type = PARSE_STAKE_SHARE_OK;

    return true;
}

uint16_t status_word_for_failed_to_parse_stake_share(parse_stake_share_outcome_e failure_reason) {
    switch (failure_reason) {
        case PARSE_STAKE_SHARE_OK:
            return SW_OK;
        case PARSE_STAKE_SHARE_FAILURE_PARSE_PUBLICKEY:
            return ERR_CMD_SIGN_TX_STAKE_SHARE_PARSE_PUBLIC_KEY_FAILURE;
        case PARSE_STAKE_SHARE_FAILURE_PARSE_OWNER:
            return ERR_CMD_SIGN_TX_STAKE_SHARE_PARSE_OWNER_FAILURE;
        case PARSE_STAKE_SHARE_FAILURE_PARSE_AMOUNT:
            return ERR_CMD_SIGN_TX_STAKE_SHARE_PARSE_AMOUNT_FAILURE;
    }
}

void print_parse_stake_share_outcome(parse_stake_share_outcome_t *outcome) {
    PRINTF("parse stake share outcome: ");
    switch (outcome->outcome_type) {
        case PARSE_STAKE_SHARE_OK:
            PRINTF("'OK'");
            break;
        case PARSE_STAKE_SHARE_FAILURE_PARSE_PUBLICKEY:
            PRINTF("'FAILURE_PARSE_PUBLICKEY'");
            break;
        case PARSE_STAKE_SHARE_FAILURE_PARSE_OWNER:
            PRINTF("'FAILURE_PARSE_OWNER' - printing reason:\n");
            print_parse_address_failure_reason(outcome->owner_parse_failure_reason);
            break;
        case PARSE_STAKE_SHARE_FAILURE_PARSE_AMOUNT:
            PRINTF("'FAILURE_PARSE_AMOUNT'");
            break;
    }
    PRINTF("\n");
}