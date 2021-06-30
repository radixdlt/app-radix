#include "validator_allow_delegation_flag.h"
#include "../../sw.h"

#include "../../bridge.h"

bool parse_validator_allow_delegation_flag(
    buffer_t *buffer,
    parse_validator_allow_delegation_flag_outcome_e *outcome,
    validator_allow_delegation_flag_t *validator_allow_delegation_flag) {
    // Parse field 'reserved'
    if (!buffer_read_u8(buffer, &validator_allow_delegation_flag->reserved)) {
        PRINTF("Failed to parse 'delegate' in substate 'VALIDATOR_ALLOW_DELEGATION_FLAG'.\n");
        *outcome = PARSE_VALIDATOR_ALLOW_DELEGATION_FLAG_FAILURE_RESERVED;
        return false;
    }

    // Parse field 'validator'.
    if (!buffer_move_fill_target(
            buffer,
            (uint8_t *) &validator_allow_delegation_flag->validator.public_key.compressed,
            PUBLIC_KEY_COMPRESSED_LEN)) {
        PRINTF("Failed to parse 'validator' in substate 'VALIDATOR_ALLOW_DELEGATION_FLAG'.\n");
        *outcome = PARSE_VALIDATOR_ALLOW_DELEGATION_FLAG_FAILURE_VALIDATOR;
        return false;
    }
    validator_allow_delegation_flag->validator.address_type = RE_ADDRESS_PUBLIC_KEY;

    // Parse field 'is_delegation_allowed'
    uint8_t is_delegation_allowed_value;
    if (!buffer_read_u8(buffer, &is_delegation_allowed_value)) {
        PRINTF(
            "Failed to parse 'is_delegation_allowed' in substate "
            "'VALIDATOR_ALLOW_DELEGATION_FLAG'.\n");
        *outcome = PARSE_VALIDATOR_ALLOW_DELEGATION_FLAG_FAILURE_IS_DELEGATION_ALLOWED;
        return false;
    }
    validator_allow_delegation_flag->is_delegation_allowed = is_delegation_allowed_value == 1;

    // Finished parsing.
    *outcome = PARSE_VALIDATOR_ALLOW_DELEGATION_FLAG_OK;

    return true;
}

uint16_t status_word_for_failed_to_parse_validator_allow_delegation_Flag(
    parse_validator_allow_delegation_flag_outcome_e failure_reason) {
    switch (failure_reason) {
        case PARSE_VALIDATOR_ALLOW_DELEGATION_FLAG_OK:
            return SW_OK;
        case PARSE_VALIDATOR_ALLOW_DELEGATION_FLAG_FAILURE_RESERVED:
            return ERR_CMD_SIGN_TX_VALIDATOR_ALLOW_DELEGATION_FLAG_RESERVED_FAILURE;
        case PARSE_VALIDATOR_ALLOW_DELEGATION_FLAG_FAILURE_VALIDATOR:
            return ERR_CMD_SIGN_TX_VALIDATOR_ALLOW_DELEGATION_FLAG_VALIDATOR_FAILURE;
        case PARSE_VALIDATOR_ALLOW_DELEGATION_FLAG_FAILURE_IS_DELEGATION_ALLOWED:
            return ERR_CMD_SIGN_TX_VALIDATOR_ALLOW_DELEGATION_FLAG_IS_DELEGATION_ALLOWED_FAILURE;
    }

    return ERR_BAD_STATE;  // should never happen
}
