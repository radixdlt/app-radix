#pragma once

#include "../../sw.h"
#include "../../constants.h"

#include "../../types/re_address.h"
#include "../../types/uint256.h"
#include "../../types/public_key.h"
#include "../../types/buffer.h"

typedef struct {
    re_address_t owner;
    re_address_t
        delegate;  // Actually host machine will stream a public key to the Ledger device, but since
                   // we are going to display it, we will put it in public_key of the address.
    uint256_t amount;
} prepared_stake_t;

typedef enum {
    PARSE_PREPARED_STAKE_OK = 0,
    PARSE_PREPARED_STAKE_FAILURE_PARSE_OWNER = 1,
    PARSE_PREPARED_STAKE_FAILURE_PARSE_DELEGATE = 2,
    PARSE_PREPARED_STAKE_FAILURE_PARSE_AMOUNT = 3,
} parse_prepared_stake_outcome_e;

typedef struct {
    parse_prepared_stake_outcome_e outcome_type;
    union {
        parse_address_failure_reason_e parse_owner_failure;
    };
} parse_prepared_stake_outcome_t;

bool parse_prepared_stake(buffer_t *buffer,
                          parse_prepared_stake_outcome_t *outcome,
                          prepared_stake_t *prepared_stake);

uint16_t status_word_for_failed_to_parse_prepared_stake(
    parse_prepared_stake_outcome_e failure_reason);

void print_parse_prepared_stake_outcome(parse_prepared_stake_outcome_t *outcome);