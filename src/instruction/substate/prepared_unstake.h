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
} prepared_unstake_t;

typedef enum {
    PARSE_PREPARED_UNSTAKE_OK,
    PARSE_PREPARED_UNSTAKE_FAILURE_PARSE_RESERVED,
    PARSE_PREPARED_UNSTAKE_FAILURE_PARSE_VALIDATOR,
    PARSE_PREPARED_UNSTAKE_FAILURE_PARSE_OWNER,
    PARSE_PREPARED_UNSTAKE_FAILURE_PARSE_AMOUNT,
} parse_prepared_unstake_outcome_e;

typedef struct {
    parse_prepared_unstake_outcome_e outcome_type;
    union {
        parse_address_failure_reason_e owner_parse_failure_reason;
    };
} parse_prepared_unstake_outcome_t;

bool parse_prepared_unstake(buffer_t *buffer,
                            parse_prepared_unstake_outcome_t *outcome,
                            prepared_unstake_t *prepared_unstake);

uint16_t status_word_for_failed_to_parse_prepared_unstake(
    parse_prepared_unstake_outcome_e failure_reason);
