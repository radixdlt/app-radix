#include "substate.h"
#include "../../sw_custom.h"

#include "../../bridge.h"  // PRINTF

bool parse_substate(buffer_t *buffer, parse_substate_outcome_t *outcome, substate_t *substate) {
    uint8_t substate_type_value;
    if (!buffer_read_u8(buffer, &substate_type_value) ||
        !is_re_substate_type_known((int) substate_type_value)) {
        PRINTF("ERROR unrecognized substate type: %d\n", substate_type_value);
        outcome->outcome_type = PARSE_SUBSTATE_FAIL_UNRECOGNIZED_SUBSTATE_TYPE;
        outcome->unrecognized_substate_type_value = substate_type_value;
        return false;
    }

    if (!is_re_substate_type_supported((int) substate_type_value)) {
        PRINTF("ERROR unsupported substate type: %d\n", substate_type_value);
        outcome->outcome_type = PARSE_SUBSTATE_FAIL_UNSUPPORTED_SUBSTATE_TYPE;
        outcome->unsupported_substate_type_value = substate_type_value;
        return false;
    }

    substate->type = (re_substate_type_e) substate_type_value;

    // print_re_substate_type(substate->type);

    switch (substate->type) {
        case SUBSTATE_TYPE_TOKENS:
            if (!parse_tokens(buffer, &outcome->tokens_failure, &substate->tokens)) {
                PRINTF("Failed to parse 'TOKENS'.\n");
                outcome->outcome_type = PARSE_SUBSTATE_FAILED_TO_PARSE_TOKENS;
                return false;
            }
            PRINTF("Successfully parsed substate of type 'TOKENS'.\n");
            break;
        case SUBSTATE_TYPE_PREPARED_STAKE:
            if (!parse_prepared_stake(buffer,
                                      &outcome->prepared_stake_failure,
                                      &substate->prepared_stake)) {
                PRINTF("Failed to parse 'PREPARE_STAKE'.\n");

                outcome->outcome_type = PARSE_SUBSTATE_FAILED_TO_PARSE_PREPARED_STAKE;
                return false;
            }
            PRINTF("Successfully parsed substate of type 'PREPARE_STAKE'.\n");
            break;
        case SUBSTATE_TYPE_STAKE_SHARE:
            if (!parse_stake_share(buffer, &outcome->stake_share_failure, &substate->stake_share)) {
                PRINTF("Failed to parse 'STAKE_SHARE'.\n");

                outcome->outcome_type = PARSE_SUBSTATE_FAILED_TO_PARSE_SHARE_STAKE;
                return false;
            }
            PRINTF("Successfully parsed substate of type 'STAKE_SHARE'.\n");
            break;
        case SUBSTATE_TYPE_PREPARED_UNSTAKE:

            if (!parse_prepared_unstake(buffer,
                                        &outcome->prepared_unstake_failure,
                                        &substate->prepared_unstake)) {
                PRINTF("Failed to parse 'PREPARE_UNSTAKE'.\n");
                outcome->outcome_type = PARSE_SUBSTATE_FAILED_TO_PARSE_PREPARED_UNSTAKE;
                return false;
            }
            PRINTF("Successfully parsed substate of type 'PREPARE_UNSTAKE'.\n");
            break;
    }
    outcome->outcome_type = PARSE_SUBSTATE_OK;
    return true;
}

uint16_t status_word_for_failed_to_parse_substate(parse_substate_outcome_t failure_reason) {
    switch (failure_reason.outcome_type) {
        case PARSE_SUBSTATE_OK:
            return SW_OK;
        case PARSE_SUBSTATE_FAIL_UNRECOGNIZED_SUBSTATE_TYPE:
            return ERR_CMD_SIGN_TX_UNRECOGNIZED_SUBSTATE_TYPE;
        case PARSE_SUBSTATE_FAIL_UNSUPPORTED_SUBSTATE_TYPE:
            return ERR_CMD_SIGN_TX_UNSUPPORTED_SUBSTATE_TYPE;
        case PARSE_SUBSTATE_FAILED_TO_PARSE_TOKENS:
            return status_word_for_failed_to_parse_tokens(
                failure_reason.tokens_failure.outcome_type);
        case PARSE_SUBSTATE_FAILED_TO_PARSE_PREPARED_STAKE:
            return status_word_for_failed_to_parse_prepared_stake(
                failure_reason.prepared_stake_failure.outcome_type);
        case PARSE_SUBSTATE_FAILED_TO_PARSE_PREPARED_UNSTAKE:
            return status_word_for_failed_to_parse_prepared_unstake(
                failure_reason.prepared_unstake_failure.outcome_type);
        case PARSE_SUBSTATE_FAILED_TO_PARSE_SHARE_STAKE:
            return status_word_for_failed_to_parse_stake_share(
                failure_reason.stake_share_failure.outcome_type);
    }

    return ERR_BAD_STATE;  // should never happen
}
