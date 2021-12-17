#pragma once

#include "../../types/re_address.h"
#include "../../types/uint256.h"
#include "../../types/public_key.h"
#include "../../types/buffer.h"

typedef struct {
    uint8_t reserved;
    // The validator public key
    re_address_t validator;  // Actually host machine will stream a public key to the Ledger device,
                             // but since we are going to display it, we will put it in public_key
                             // of the address.
    re_address_t owner;
    uint256_t amount;
} stake_ownership_t;

typedef enum {
    PARSE_STAKE_OWNERSHIP_OK,
    PARSE_STAKE_OWNERSHIP_FAILURE_PARSE_RESERVED,
    PARSE_STAKE_OWNERSHIP_FAILURE_PARSE_VALIDATOR,
    PARSE_STAKE_OWNERSHIP_FAILURE_PARSE_OWNER,
    PARSE_STAKE_OWNERSHIP_FAILURE_PARSE_AMOUNT,
} parse_stake_ownership_outcome_e;

typedef struct {
    parse_stake_ownership_outcome_e outcome_type;
    union {
        parse_address_failure_reason_e owner_parse_failure_reason;
    };
} parse_stake_ownership_outcome_t;

bool parse_stake_ownership(buffer_t *buffer,
                           parse_stake_ownership_outcome_t *outcome,
                           stake_ownership_t *stake_ownership);

uint16_t status_word_for_failed_to_parse_stake_ownership(
    parse_stake_ownership_outcome_e failure_reason);
