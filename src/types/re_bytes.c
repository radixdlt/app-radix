#include "re_bytes.h"

#include "../sw.h"
#include "../bridge.h"

bool parse_re_bytes(buffer_t *buffer, parse_bytes_outcome_e *outcome, re_bytes_t *bytes) {
    if (!buffer_read_u16(buffer, &bytes->length, BE)) {
        PRINTF("Failed to parse length of RE bytes.\n");
        *outcome = PARSE_BYTES_FAILED_TO_PARSE_LENGTH;
        return false;
    }

    if (bytes->length >= MAX_BYTES_LEN ||
            !buffer_move_fill_target(buffer, bytes->data, bytes->length)) {
        PRINTF("Failed to parse RE bytes, wrong length, first byte specified length of %d\n",
               bytes->length);
        *outcome = PARSE_BYTES_FAIL_WRONG_LENGTH;
        return false;
    }

    *outcome = PARSE_BYTES_OK;

    return true;
}

uint16_t status_word_for_failed_to_parse_bytes(parse_bytes_outcome_e outcome) {
    switch (outcome) {
        case PARSE_BYTES_OK:
            return SW_OK;
        case PARSE_BYTES_FAILED_TO_PARSE_LENGTH:
            return ERR_CMD_SIGN_TX_PARSE_BYTES_LENGTH_FAILURE;
        case PARSE_BYTES_FAIL_WRONG_LENGTH:
            return ERR_CMD_SIGN_TX_PARSE_BYTES_WRONG_LENGTH;
    }

    return ERR_BAD_STATE;  // should never happen
}
