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
        case SUBSTATE_TYPE_STAKE_OWNERSHIP:
            if (!parse_stake_ownership(buffer,
                                       &outcome->stake_ownership_failure,
                                       &substate->stake_ownership)) {
                PRINTF("Failed to parse 'STAKE_OWNERSHIP'.\n");

                outcome->outcome_type = PARSE_SUBSTATE_FAILED_TO_PARSE_STAKE_OWNERSHIP;
                return false;
            }
            PRINTF("Successfully parsed substate of type 'STAKE_OWNERSHIP'.\n");
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
        case SUBSTATE_TYPE_VALIDATOR_OWNER_COPY:
            if (!parse_validator_owner_copy(buffer,
                                            &outcome->validator_owner_copy_failure,
                                            &substate->validator_owner_copy)) {
                PRINTF("Failed to parse 'VALIDATOR_OWNER_COPY'.\n");
                outcome->outcome_type = PARSE_SUBSTATE_FAILED_TO_PARSE_VALIDATOR_OWNER_COPY;
                return false;
            }
            PRINTF("Successfully parsed substate of type 'VALIDATOR_OWNER_COPY'.\n");
            break;
        case SUBSTATE_TYPE_VALIDATOR_ALLOW_DELEGATION_FLAG:
            if (!parse_validator_allow_delegation_flag(
                    buffer,
                    &outcome->validator_allow_delegation_flag_failure,
                    &substate->validator_allow_delegation_flag)) {
                PRINTF("Failed to parse 'VALIDATOR_ALLOW_DELEGATION_FLAG'.\n");
                outcome->outcome_type =
                    PARSE_SUBSTATE_FAILED_TO_PARSE_VALIDATOR_ALLOW_DELEGATION_FLAG;
                return false;
            }
            PRINTF("Successfully parsed substate of type 'VALIDATOR_ALLOW_DELEGATION_FLAG'.\n");
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
        case PARSE_SUBSTATE_FAILED_TO_PARSE_STAKE_OWNERSHIP:
            return status_word_for_failed_to_parse_stake_ownership(
                failure_reason.stake_ownership_failure.outcome_type);
        case PARSE_SUBSTATE_FAILED_TO_PARSE_PREPARED_UNSTAKE:
            return status_word_for_failed_to_parse_prepared_unstake(
                failure_reason.prepared_unstake_failure.outcome_type);
        case PARSE_SUBSTATE_FAILED_TO_PARSE_VALIDATOR_OWNER_COPY:
            return status_word_for_failed_to_parse_validator_owner_copy(
                failure_reason.validator_owner_copy_failure.outcome_type);
        case PARSE_SUBSTATE_FAILED_TO_PARSE_VALIDATOR_ALLOW_DELEGATION_FLAG:
            return status_word_for_failed_to_parse_validator_allow_delegation_Flag(
                failure_reason.validator_allow_delegation_flag_failure);
    }

    return ERR_BAD_STATE;  // should never happen
}
