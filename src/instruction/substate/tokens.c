#include "tokens.h"
#include "../../sw.h"
#include "../macros.h"  // ASSERT

bool parse_tokens(buffer_t *buffer, parse_tokens_outcome_t *outcome, tokens_t *tokens) {
    parse_address_failure_reason_e parse_address_failure;

    // Parse field 'rri'
    if (!parse_re_address(buffer, &parse_address_failure, &tokens->rri)) {
        PRINTF("Failed to parse 'rri' in substate 'TOKENS'.\n");
        outcome->outcome_type = PARSE_TOKENS_FAILURE_PARSE_RRI;
        outcome->rri_parse_failure_reason = parse_address_failure;
        return false;
    }

    // Parse field 'owner'
    if (!parse_re_address(buffer, &parse_address_failure, &tokens->owner)) {
        PRINTF("Failed to parse 'owner' in substate 'TOKENS'.\n");
        outcome->outcome_type = PARSE_TOKENS_FAILURE_PARSE_OWNER;
        outcome->owner_parse_failure_reason = parse_address_failure;
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
}

void print_parse_tokens_outcome(parse_tokens_outcome_t *outcome) {
    PRINTF("parse tokens outcome: ");
    switch (outcome->outcome_type) {
        case PARSE_TOKENS_OK:
            PRINTF("'OK'");
            break;
        case PARSE_TOKENS_FAILURE_PARSE_RRI:
            PRINTF("'FAILURE_PARSE_RRI' - printing reason:\n");
            print_parse_address_failure_reason(outcome->rri_parse_failure_reason);
            break;
        case PARSE_TOKENS_FAILURE_PARSE_OWNER:
            PRINTF("'FAILURE_PARSE_OWNER' - printing reason:\n");
            print_parse_address_failure_reason(outcome->owner_parse_failure_reason);
            break;
        case PARSE_TOKENS_FAILURE_PARSE_AMOUNT:
            PRINTF("'FAILURE_PARSE_AMOUNT'");
            break;
    }
    PRINTF("\n");
}

bool does_tokens_need_to_be_displayed(tokens_t *tokens, public_key_t *my_public_key) {
    ASSERT(tokens->owner.address_type == RE_ADDRESS_PUBLIC_KEY,
           "Owner of tokens should be of Radix Address type 'PUBLICKEY'");

    // We do not need to display tokens that are sent back to user (change).
    return !public_key_equals(&tokens->owner.public_key, my_public_key);
}