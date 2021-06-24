#include "tokens.h"
#include "../../sw.h"
#include "../../bridge.h"  // PRINTF
// #include "../macros.h"  // ASSERT

bool parse_tokens(buffer_t *buffer, parse_tokens_outcome_t *outcome, tokens_t *tokens) {
    // Parse field 'rri'
    if (!parse_re_address(buffer, &outcome->rri_parse_failure_reason, &tokens->rri)) {
        PRINTF("Failed to parse 'rri' in substate 'TOKENS'.\n");
        outcome->outcome_type = PARSE_TOKENS_FAILURE_PARSE_RRI;
        return false;
    }

    if (tokens->rri.address_type != RE_ADDRESS_HASHED_KEY_NONCE &&
        tokens->rri.address_type != RE_ADDRESS_NATIVE_TOKEN) {
        // Wrong address type in context of RRI.
        outcome->outcome_type = PARSE_TOKENS_FAILURE_PARSE_RRI;
        outcome->rri_parse_failure_reason = PARSED_ADDRESS_FAIL_EXPECTED_TYPE_COMPATIBLE_WITH_RRI;
        return false;
    }

    // Parse field 'owner'
    if (!parse_re_address(buffer, &outcome->owner_parse_failure_reason, &tokens->owner)) {
        PRINTF("Failed to parse 'owner' in substate 'TOKENS'.\n");
        outcome->outcome_type = PARSE_TOKENS_FAILURE_PARSE_OWNER;
        return false;
    }

    if (tokens->owner.address_type != RE_ADDRESS_PUBLIC_KEY) {
        // Wrong address type in context of account address.
        outcome->outcome_type = PARSE_TOKENS_FAILURE_PARSE_OWNER;
        outcome->owner_parse_failure_reason =
            PARSED_ADDRESS_FAIL_EXPECTED_TYPE_COMPATIBLE_ACCOUNT_OR_VALIDATOR_ADDRESS;
        return false;
    }

    // Parse field 'amount'
    if (!uint256_from_buffer(buffer, &tokens->amount)) {
        PRINTF("Failed to parse 'amount' in substate 'TOKENS'.\n");
        outcome->outcome_type = PARSE_TOKENS_FAILURE_PARSE_AMOUNT;
        return false;
    }

    outcome->outcome_type = PARSE_TOKENS_OK;

    return true;
}

uint16_t status_word_for_failed_to_parse_tokens(parse_tokens_outcome_e failure_reason) {
    switch (failure_reason) {
        case PARSE_TOKENS_OK:
            return SW_OK;
        case PARSE_TOKENS_FAILURE_PARSE_RRI:
            return ERR_CMD_SIGN_TX_TOKENS_PARSE_RRI_FAILURE;
        case PARSE_TOKENS_FAILURE_PARSE_OWNER:
            return ERR_CMD_SIGN_TX_TOKENS_PARSE_OWNER_FAILURE;
        case PARSE_TOKENS_FAILURE_PARSE_AMOUNT:
            return ERR_CMD_SIGN_TX_TOKENS_PARSE_AMOUNT_FAILURE;
    }

    return ERR_BAD_STATE;  // should never happen
}