#pragma once

#include "../../types/buffer.h"
#include "../../types/public_key.h"

#include "substate_type.h"
#include "tokens.h"
#include "prepared_stake.h"
#include "prepared_unstake.h"
#include "validator_allow_delegation_flag.h"
#include "validator_owner_copy.h"

typedef struct {
    re_substate_type_e type;
    union {
        tokens_t tokens;
        prepared_stake_t prepared_stake;
        prepared_unstake_t prepared_unstake;
        validator_allow_delegation_flag_t validator_allow_delegation_flag;
        validator_owner_copy_t validator_owner_copy;
    };
} substate_t;

typedef enum {
    PARSE_SUBSTATE_OK = 0,

    PARSE_SUBSTATE_FAIL_UNRECOGNIZED_SUBSTATE_TYPE = 1,
    PARSE_SUBSTATE_FAIL_UNSUPPORTED_SUBSTATE_TYPE = 2,

    PARSE_SUBSTATE_FAILED_TO_PARSE_TOKENS = 3,
    PARSE_SUBSTATE_FAILED_TO_PARSE_PREPARED_STAKE = 4,
    PARSE_SUBSTATE_FAILED_TO_PARSE_PREPARED_UNSTAKE = 5,
    PARSE_SUBSTATE_FAILED_TO_PARSE_VALIDATOR_ALLOW_DELEGATION_FLAG = 6,
    PARSE_SUBSTATE_FAILED_TO_PARSE_VALIDATOR_OWNER_COPY = 7,
} parse_substate_outcome_type_e;

typedef struct {
    parse_substate_outcome_type_e outcome_type;
    union {
        uint8_t unrecognized_substate_type_value;
        uint8_t unsupported_substate_type_value;
        parse_tokens_outcome_t tokens_failure;
        parse_prepared_stake_outcome_t prepared_stake_failure;
        parse_prepared_unstake_outcome_t prepared_unstake_failure;
        parse_validator_allow_delegation_flag_outcome_e validator_allow_delegation_flag_failure;
        parse_validator_owner_copy_outcome_t validator_owner_copy_failure;
    };
} parse_substate_outcome_t;

bool parse_substate(buffer_t *buffer, parse_substate_outcome_t *outcome, substate_t *substate);

uint16_t status_word_for_failed_to_parse_substate(parse_substate_outcome_t failure_reason);