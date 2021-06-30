#include "validator_owner_copy.h"
#include "../../sw.h"

#include "../../bridge.h"

bool parse_validator_owner_copy(buffer_t *buffer,
                                parse_validator_owner_copy_outcome_t *outcome,
                                validator_owner_copy_t *validator_owner_copy) {
    // Parse field 'reserved'
    if (!buffer_read_u8(buffer, &validator_owner_copy->reserved)) {
        PRINTF("Failed to parse 'delegate' in substate 'VALIDATOR_OWNER_COPY'.\n");
        outcome->outcome_type = PARSE_VALIDATOR_OWNER_COPY_FAILURE_RESERVED;
        return false;
    }

    // Parse field 'validator'.
    if (!buffer_move_fill_target(buffer,
                                 (uint8_t *) &validator_owner_copy->validator.public_key.compressed,
                                 PUBLIC_KEY_COMPRESSED_LEN)) {
        PRINTF("Failed to parse 'validator' in substate 'VALIDATOR_OWNER_COPY'.\n");
        outcome->outcome_type = PARSE_VALIDATOR_OWNER_COPY_FAILURE_VALIDATOR;
        return false;
    }
    validator_owner_copy->validator.address_type = RE_ADDRESS_PUBLIC_KEY;

    // Parse field 'owner'
    if (!parse_re_address(buffer, &outcome->parse_owner_failure, &validator_owner_copy->owner)) {
        PRINTF("Failed to parse 'owner' in substate 'VALIDATOR_OWNER_COPY'.\n");
        outcome->outcome_type = PARSE_VALIDATOR_OWNER_COPY_FAILURE_OWNER;
        return false;
    }

    // Finished parsing.
    outcome->outcome_type = PARSE_VALIDATOR_OWNER_COPY_OK;

    return true;
}

uint16_t status_word_for_failed_to_parse_validator_owner_copy(
    parse_validator_owner_copy_outcome_e failure_reason) {
    switch (failure_reason) {
        case PARSE_VALIDATOR_OWNER_COPY_OK:
            return SW_OK;
        case PARSE_VALIDATOR_OWNER_COPY_FAILURE_RESERVED:
            return ERR_CMD_SIGN_TX_VALIDATOR_OWNER_COPY_RESERVED_FAILURE;
        case PARSE_VALIDATOR_OWNER_COPY_FAILURE_VALIDATOR:
            return ERR_CMD_SIGN_TX_VALIDATOR_OWNER_COPY_VALIDATOR_FAILURE;
        case PARSE_VALIDATOR_OWNER_COPY_FAILURE_OWNER:
            return ERR_CMD_SIGN_TX_VALIDATOR_OWNER_COPY_OWNER_FAILURE;
    }

    return ERR_BAD_STATE;  // should never happen
}
