#include "tokens.h"
#include "../../sw.h"
#include "../../bridge.h"  // PRINTF
// #include "../macros.h"  // ASSERT

bool parse_tokens(buffer_t *buffer, parse_tokens_outcome_t *outcome, tokens_t *tokens) {
    // Parse field 'reserved'
    if (!buffer_read_u8(buffer, &tokens->reserved)) {
        PRINTF("Failed to parse 'reserved' in substate 'TOKENS'.\n");
        outcome->outcome_type = PARSE_TOKENS_FAILURE_PARSE_RESERVED;
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

    // Parse field 'resource'
    if (!parse_re_address(buffer, &outcome->resource_parse_failure_reason, &tokens->resource)) {
        PRINTF("Failed to parse 'resource' in substate 'TOKENS'.\n");
        outcome->outcome_type = PARSE_TOKENS_FAILURE_PARSE_RESOURCE;
        return false;
    }
    if (tokens->resource.address_type != RE_ADDRESS_HASHED_KEY_NONCE &&
        tokens->resource.address_type != RE_ADDRESS_NATIVE_TOKEN) {
        // Wrong address type in context of Resource.
        outcome->outcome_type = PARSE_TOKENS_FAILURE_PARSE_RESOURCE;
        outcome->resource_parse_failure_reason =
            PARSED_ADDRESS_FAIL_EXPECTED_TYPE_COMPATIBLE_WITH_RESOURCE;
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
        case PARSE_TOKENS_FAILURE_PARSE_RESERVED:
            return ERR_CMD_SIGN_TX_TOKENS_PARSE_RESERVED_FAILURE;
        case PARSE_TOKENS_FAILURE_PARSE_OWNER:
            return ERR_CMD_SIGN_TX_TOKENS_PARSE_OWNER_FAILURE;
        case PARSE_TOKENS_FAILURE_PARSE_RESOURCE:
            return ERR_CMD_SIGN_TX_TOKENS_PARSE_RESOURCE_FAILURE;
        case PARSE_TOKENS_FAILURE_PARSE_AMOUNT:
            return ERR_CMD_SIGN_TX_TOKENS_PARSE_AMOUNT_FAILURE;
    }

    return ERR_BAD_STATE;  // should never happen
}