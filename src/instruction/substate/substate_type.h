#pragma once

#include <stdbool.h>
#include <stdint.h>

#define RE_SUBSTATE_TYPE_LAST_KNOWN 0x11

/**
 * @brief Type of substate, e.g. TOKENS, STAKE, UNSTAKE or STAKE_OWNERSHIP.
 *
 */
typedef enum {
    // SUBSTATE_TYPE_VIRTUAL_PARENT = 0x00,
    // SUBSTATE_TYPE_UNCLAIMED_READDR = 0x01,
    // SUBSTATE_TYPE_ROUND_DATA = 0x02,
    // SUBSTATE_TYPE_EPOCH_DATA = 0x03,
    // SUBSTATE_TYPE_TOKEN_RESOURCE = 0x04,
    // SUBSTATE_TYPE_TOKEN_RESOURCE_METADATA = 0x05,
    SUBSTATE_TYPE_TOKENS = 0x06,
    SUBSTATE_TYPE_PREPARED_STAKE = 0x07,
    SUBSTATE_TYPE_STAKE_OWNERSHIP = 0x08,
    SUBSTATE_TYPE_PREPARED_UNSTAKE = 0x09,
    // SUBSTATE_TYPE_EXITTING_STAKE = 0x0A,
    // SUBSTATE_TYPE_VALIDATOR_META_DATA = 0x0B,
    // SUBSTATE_TYPE_VALIDATOR_STAKE_DATA = 0x0C,
    // SUBSTATE_TYPE_VALIDATOR_BFT_DATA = 0x0D,
    SUBSTATE_TYPE_VALIDATOR_ALLOW_DELEGATION_FLAG = 0x0E,
    // SUBSTATE_TYPE_VALIDATOR_REGISTERED_FLAG_COPY = 0x0F,
    // SUBSTATE_TYPE_VALIDATOR_RAKE_COPY = 0x10,
    SUBSTATE_TYPE_VALIDATOR_OWNER_COPY = 0x11,
} re_substate_type_e;

bool is_re_substate_type_known(uint8_t raw);

bool is_re_substate_type_supported(uint8_t raw);
