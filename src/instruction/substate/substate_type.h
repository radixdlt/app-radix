#pragma once

#include <stdbool.h>

#define RE_SUBSTATE_TYPE_LAST_KNOWN 0x0e

/**
 * @brief Type of substate, e.g. TOKENS, STAKE, UNSTAKE or STAKE_SHARE.
 *
 */
typedef enum {
    // SUBSTATE_TYPE_RE_ADDRESS = 0x00,         // Unsupported
    // SUBSTATE_TYPE_TOKEN_DEFINITION = 0x02,   // Unsupported
    SUBSTATE_TYPE_TOKENS = 0x03,
    SUBSTATE_TYPE_PREPARED_STAKE = 0x04,
    // SUBSTATE_TYPE_VALIDATOR = 0x05,          // Unsupported
    // SUBSTATE_TYPE_UNIQUE = 0x06,             // Unsupported
    SUBSTATE_TYPE_STAKE_SHARE = 0x0b,
    SUBSTATE_TYPE_PREPARED_UNSTAKE = 0x0d,
    // SUBSTATE_TYPE_EXITING_STAKE = 0x0e,      // Unsupported
} re_substate_type_e;

bool is_re_substate_type_known(int raw);

bool is_re_substate_type_supported(int raw);
