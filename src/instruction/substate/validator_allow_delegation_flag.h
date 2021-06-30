#pragma once

#include <stdint.h>
#include "../../types/re_address.h"

typedef struct {
    uint8_t reserved;
    // The validator public key
    re_address_t validator;  // Actually host machine will stream a public key to the Ledger device,
                             // but since we are going to display it, we will put it in public_key
                             // of the address.
    bool is_delegation_allowed;
} validator_allow_delegation_flag_t;

typedef enum {
    PARSE_VALIDATOR_ALLOW_DELEGATION_FLAG_OK,

    PARSE_VALIDATOR_ALLOW_DELEGATION_FLAG_FAILURE_RESERVED,
    PARSE_VALIDATOR_ALLOW_DELEGATION_FLAG_FAILURE_VALIDATOR,
    PARSE_VALIDATOR_ALLOW_DELEGATION_FLAG_FAILURE_IS_DELEGATION_ALLOWED,
} parse_validator_allow_delegation_flag_outcome_e;

bool parse_validator_allow_delegation_flag(
    buffer_t *buffer,
    parse_validator_allow_delegation_flag_outcome_e *outcome,
    validator_allow_delegation_flag_t *validator_allow_delegation_flag);

uint16_t status_word_for_failed_to_parse_validator_allow_delegation_Flag(
    parse_validator_allow_delegation_flag_outcome_e failure_reason);
