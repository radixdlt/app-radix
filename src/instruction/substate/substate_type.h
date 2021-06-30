#pragma once

#include <stdbool.h>
#include <stdint.h>

// VALIDATOR_OWNER_COPY
#define RE_SUBSTATE_TYPE_LAST_KNOWN 0x12

/**
 * @brief Type of substate, e.g. TOKENS, STAKE, UNSTAKE or STAKE_OWNERSHIP.
 *
 */
typedef enum {
    SUBSTATE_TYPE_TOKENS = 0x05,
    SUBSTATE_TYPE_PREPARED_STAKE = 0x06,
    SUBSTATE_TYPE_STAKE_OWNERSHIP = 0x07,
    SUBSTATE_TYPE_PREPARED_UNSTAKE = 0x08,
    SUBSTATE_TYPE_VALIDATOR_ALLOW_DELEGATION_FLAG = 0x0d,
    SUBSTATE_TYPE_VALIDATOR_OWNER_COPY = 0x12,
} re_substate_type_e;

bool is_re_substate_type_known(uint8_t raw);

bool is_re_substate_type_supported(uint8_t raw);
