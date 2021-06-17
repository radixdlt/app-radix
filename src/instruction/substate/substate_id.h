#pragma once

#include <stdint.h>           // uint8_t, uint32_t
#include "../../constants.h"  // HASH_LEN
#include "../../types/buffer.h"

#define SUBSTATE_ID_HASH_LEN HASH_LEN

/**
 * Structure the RE substate id
 */
typedef struct {
    uint8_t hash[SUBSTATE_ID_HASH_LEN];
    uint32_t index;
} substate_id_t;

typedef enum {
    PARSE_SUBSTATE_ID_OK = 0,
    PARSE_SUBSTATE_ID_FAILED_HASH = 1,
    PARSE_SUBSTATE_ID_FAILED_INDEX = 2,
} parse_substate_id_outcome_e;

bool parse_substate_id(buffer_t *buffer,
                       parse_substate_id_outcome_e *outcome,
                       substate_id_t *substate_id);

uint16_t status_word_for_failed_to_parse_substate_id(parse_substate_id_outcome_e outcome);
