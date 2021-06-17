#pragma once

#include "../../types/re_address.h"
#include "../../types/uint256.h"
#include "../../types/public_key.h"

typedef struct {
    re_address_t rri;
    re_address_t owner;
    uint256_t amount;
} tokens_t;

/**
 * @brief Outcome of tokens parsing, either OK or some failure.
 *
 */
typedef enum {
    PARSE_TOKENS_OK = 0,
    PARSE_TOKENS_FAILURE_PARSE_RRI = 1,
    PARSE_TOKENS_FAILURE_PARSE_OWNER = 2,
    PARSE_TOKENS_FAILURE_PARSE_AMOUNT = 3,
} parse_tokens_outcome_e;

typedef struct {
    parse_tokens_outcome_e outcome_type;
    union {
        parse_address_failure_reason_e rri_parse_failure_reason;
        parse_address_failure_reason_e owner_parse_failure_reason;
    };
} parse_tokens_outcome_t;

/**
 * @brief Parse \em tokens substate.
 *
 * Parse a substate of type \struct tokens_t from the \p buffer. The outcome of the parsing is put
 * in \p outcome, which will contain failure reason if parsing was unsuccessful. If parsing was
 * successful, the outcome is put in \p tokens and return \code true, else \code false.
 *
 * @param[in] buffer A buffer to read tokens data from.
 * @param[out] outcome If parsing was successful: \code OK, else the failure reason, @see
 * parse_tokens_outcome_e.
 * @param[out] tokens if parsing was successful, this contains the parsed \struct tokens_t.
 * @return true if parsing was successful.
 * @return false if parsing failed.
 */
bool parse_tokens(buffer_t *buffer, parse_tokens_outcome_t *outcome, tokens_t *tokens);

uint16_t status_word_for_failed_to_parse_tokens(parse_tokens_outcome_e failure_reason);