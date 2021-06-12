#pragma once

#include "../re_address.h"
#include "../uint256.h"
#include "../../constants.h"

typedef struct {
    public_key_t public_key;
    re_address_t owner;
    uint256_t amount;
} stake_share_t;

typedef enum {
    PARSE_STAKE_SHARE_OK = 0,
    PARSE_STAKE_SHARE_FAILURE_PARSE_PUBLICKEY = 1,
    PARSE_STAKE_SHARE_FAILURE_PARSE_OWNER = 2,
    PARSE_STAKE_SHARE_FAILURE_PARSE_AMOUNT = 3,
} parse_stake_share_outcome_e;

typedef struct {
    parse_stake_share_outcome_e outcome_type;
    union {
        parse_address_failure_reason_e owner_parse_failure_reason;
    };
} parse_stake_share_outcome_t;

bool parse_stake_share(buffer_t *buffer,
                       parse_stake_share_outcome_t *outcome,
                       stake_share_t *stake_share);

uint16_t status_word_for_failed_to_parse_stake_share(parse_stake_share_outcome_e failure_reason);