#pragma once

#include <stdint.h>
#include "../../types/re_address.h"

typedef struct {
    uint8_t reserved;
    // The validator public key
    re_address_t validator;  // Actually host machine will stream a public key to the Ledger device,
                             // but since we are going to display it, we will put it in public_key
                             // of the address.
    re_address_t owner;
} validator_owner_copy_t;

typedef enum {
    PARSE_VALIDATOR_OWNER_COPY_OK,

    PARSE_VALIDATOR_OWNER_COPY_FAILURE_RESERVED,
    PARSE_VALIDATOR_OWNER_COPY_FAILURE_VALIDATOR,
    PARSE_VALIDATOR_OWNER_COPY_FAILURE_OWNER,
} parse_validator_owner_copy_outcome_e;

typedef struct {
    parse_validator_owner_copy_outcome_e outcome_type;
    union {
        parse_address_failure_reason_e parse_owner_failure;
    };
} parse_validator_owner_copy_outcome_t;

bool parse_validator_owner_copy(buffer_t *buffer,
                                parse_validator_owner_copy_outcome_t *outcome,
                                validator_owner_copy_t *validator_owner_copy);

uint16_t status_word_for_failed_to_parse_validator_owner_copy(
    parse_validator_owner_copy_outcome_e failure_reason);
