#include "substate_id.h"

#include "../../sw.h"
#include "../../bridge.h"

bool parse_substate_id(buffer_t *buffer,
                       parse_substate_id_outcome_e *outcome,
                       substate_id_t *substate_id) {
    // Parse field 'hash'
    debug_print_buffer(buffer);

    PRINTF("\nAbout to parse SUBSTATE_ID, beginning with HASH, having length: %d.\n",
           SUBSTATE_ID_HASH_LEN);

    if (!buffer_move_fill_target(buffer, substate_id->hash, SUBSTATE_ID_HASH_LEN)) {
        PRINTF("Failed to parse 'hash' in substate id.\n");
        *outcome = PARSE_SUBSTATE_ID_FAILED_HASH;
        return false;
    }

    if (!buffer_read_u32(buffer, &substate_id->index, BE)) {
        PRINTF("Failed to parse 'index' in substate id.\n");
        *outcome = PARSE_SUBSTATE_ID_FAILED_INDEX;
        return false;
    }

    *outcome = PARSE_SUBSTATE_ID_OK;

    return true;
}

uint16_t status_word_for_failed_to_parse_substate_id(parse_substate_id_outcome_e outcome) {
    switch (outcome) {
        case PARSE_SUBSTATE_ID_OK:
            return SW_OK;
        case PARSE_SUBSTATE_ID_FAILED_HASH:
            return ERR_CMD_SIGN_TX_SUBSTATE_ID_HASH_PARSE_FAILURE;
        case PARSE_SUBSTATE_ID_FAILED_INDEX:
            return ERR_CMD_SIGN_TX_SUBSTATE_ID_INDEX_PARSE_FAILURE;
    }

    return ERR_BAD_STATE;  // should never happen
}
