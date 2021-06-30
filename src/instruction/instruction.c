#include "instruction.h"

#include "../sw_custom.h"

#include "../bridge.h"
#include "substate/substate.h"
#include "../types/public_key.h"

static bool parse_substate_index(buffer_t *buffer, uint32_t *i32) {
    if (!buffer_read_u32(buffer, i32, BE)) {
        PRINTF("Failed to parse 'substate index'.\n");
        return false;
    }
    return true;
}

bool parse_instruction(buffer_t *buffer,
                       parse_instruction_outcome_t *outcome,
                       re_instruction_t *instruction) {
    uint8_t re_instruction_type_value;
    if (!buffer_read_u8(buffer, &re_instruction_type_value) ||
        !is_re_ins_type_known((int) re_instruction_type_value)) {
        PRINTF("ERROR unrecognized instruction type: %d\n", re_instruction_type_value);
        outcome->outcome_type = PARSE_INS_FAIL_UNREGOZNIED_INSTRUCTION_TYPE;
        outcome->unrecognized_instruction_type_value = re_instruction_type_value;
        return false;
    }

    if (!is_re_ins_type_supported((int) re_instruction_type_value)) {
        PRINTF("ERROR unsupported instruction type: %d\n", re_instruction_type_value);
        outcome->outcome_type = PARSE_INS_FAIL_UNSUPPORTED_INSTRUCTION_TYPE;
        outcome->unsupported_instruction_type_value = re_instruction_type_value;
        return false;
    }

    instruction->ins_type = (re_instruction_type_e) re_instruction_type_value;

    // print_re_ins_type(instruction->ins_type);

    switch (instruction->ins_type) {
        case INS_DOWN:
            if (!parse_substate_id(buffer,
                                   &outcome->substate_id_failure,
                                   &instruction->ins_down.substate_id)) {
                PRINTF("Failed to parse substate id for INS_DOWN.\n");
                outcome->outcome_type = PARSE_INS_FAILED_TO_PARSE_SUBSTATE_ID;
                return false;
            }
            PRINTF("Finished parsing substate ID for INS_DOWN.\n");
            break;

        case INS_READ:
            if (!parse_substate_id(buffer,
                                   &outcome->substate_id_failure,
                                   &instruction->ins_read.substate_id)) {
                PRINTF("Failed to parse substate id for INS_READ.\n");
                outcome->outcome_type = PARSE_INS_FAILED_TO_PARSE_SUBSTATE_ID;
                return false;
            }
            PRINTF("Finished parsing substate ID for INS_READ.\n");
            break;

        case INS_LDOWN:
            if (!parse_substate_index(buffer, &instruction->ins_ldown.substate_index)) {
                PRINTF("Failed to parse substate index.\n");
                outcome->outcome_type = PARSE_INS_FAILED_TO_PARSE_SUBSTATE_INDEX;
                return false;
            }
            PRINTF("Finished parsing substate index.\n");
            break;
        case INS_UP:
            if (!parse_substate(buffer,
                                &outcome->substate_failure,
                                &instruction->ins_up.substate)) {
                PRINTF("Failed to parse substate for INS_UP.\n");
                outcome->outcome_type = PARSE_INS_FAILED_TO_PARSE_SUBSTATE;
                return false;
            }
            PRINTF("Finished parsing substate.\n");
            break;
        case INS_VREAD:
            if (!parse_substate(buffer,
                                &outcome->substate_failure,
                                &instruction->ins_vread.substate)) {
                PRINTF("Failed to parse substate for INS_VREAD.\n");
                outcome->outcome_type = PARSE_INS_FAILED_TO_PARSE_SUBSTATE;
                return false;
            }
            PRINTF("Finished parsing substate.\n");
            break;

        case INS_END:
            PRINTF("Finished parsing END of substate group (empty, nothing to parse).\n");
            break;

        case INS_MSG:  // Attached Message
            if (!parse_re_bytes(buffer, &outcome->message_failure, &instruction->ins_msg.message)) {
                PRINTF("Failed to parse INS_MSG.\n");
                outcome->outcome_type = PARSE_INS_FAILED_TO_PARSE_MSG;
                return false;
            }
            PRINTF("Finished parsing attached message.\n");
            break;
        case INS_SYSCALL:  // e.g. (only?= Transaction fee amount
            if (!parse_re_bytes(buffer,
                                &outcome->syscall_failure,
                                &instruction->ins_syscall.call_data)) {
                PRINTF("Failed to parse INS_SYSCALL.\n");
                outcome->outcome_type = PARSE_INS_FAILED_TO_PARSE_SYSCALL;
                return false;
            }

            PRINTF("Finished parsing syscall (tx fee).\n");
            break;
        case INS_HEADER:
            if (!buffer_read_u8(buffer, &instruction->ins_header.version) ||
                !buffer_read_u8(buffer, &instruction->ins_header.flag)) {
                PRINTF("Failed to parse INS_HEADER.\n");
                outcome->outcome_type = PARSE_INS_FAILED_TO_PARSE_HEADER;
                return false;
            }
            if (instruction->ins_header.version != INS_HEADER_REQUIRED_VERSION) {
                PRINTF("Parsed INS_HEADER has incorrect 'version', expected: %d, but got: %d.\n",
                       INS_HEADER_REQUIRED_VERSION,
                       instruction->ins_header.version);
                outcome->outcome_type = PARSE_INS_INVALID_HEADER;
                return false;
            }
            if (instruction->ins_header.flag !=
                INS_HEADER_FLAG_DISALLOWING_TOKEN_BURN_AND_TOKEN_MINT) {
                PRINTF(
                    "Parsed INS_HEADER has incorrect 'flag', expected: %d, but got: %d.\nThis flag "
                    "is extremely important since it is a protocol enforced option that prevents a "
                    "transaction from containing token minting and token burning. But since it is "
                    "quite complex to implement those instruction we use these flag as a simpler "
                    "solution.\n",
                    INS_HEADER_FLAG_DISALLOWING_TOKEN_BURN_AND_TOKEN_MINT,
                    instruction->ins_header.flag);
                outcome->outcome_type = PARSE_INS_INVALID_HEADER;
                return false;
            }
            PRINTF(
                "Finished parsing header. We have asserted that thix transaction CANNOT contain "
                "any instructions to burn or mint new tokens.\n");
            break;
    }
    outcome->outcome_type = PARSE_INS_OK;
    return true;
}

uint16_t status_word_for_failed_to_parse_ins(parse_instruction_outcome_t *failure) {
    switch (failure->outcome_type) {
        case PARSE_INS_OK:
            return SW_OK;
        case PARSE_INS_FAIL_UNREGOZNIED_INSTRUCTION_TYPE:
            return ERR_CMD_SIGN_TX_UNRECOGNIZED_INSTRUCTION_TYPE;
        case PARSE_INS_FAIL_UNSUPPORTED_INSTRUCTION_TYPE:
            return ERR_CMD_SIGN_TX_UNSUPPORTED_INSTRUCTION_TYPE;
        case PARSE_INS_FAILED_TO_PARSE_SUBSTATE:
            return status_word_for_failed_to_parse_substate(failure->substate_failure);
        case PARSE_INS_FAILED_TO_PARSE_SUBSTATE_ID:
            return status_word_for_failed_to_parse_substate_id(failure->substate_id_failure);
        case PARSE_INS_FAILED_TO_PARSE_SUBSTATE_INDEX:
            return ERR_CMD_SIGN_TX_SUBSTATE_INDEX_PARSE_FAILURE;
        case PARSE_INS_FAILED_TO_PARSE_MSG:
            return status_word_for_failed_to_parse_bytes(failure->message_failure);
        case PARSE_INS_FAILED_TO_PARSE_HEADER:
            return ERR_CMD_SIGN_TX_PARSE_INS_HEADER;
        case PARSE_INS_INVALID_HEADER:
            return ERR_CMD_SIGN_TX_DISABLE_MINT_AND_BURN_FLAG_NOT_SET;
        case PARSE_INS_FAILED_TO_PARSE_SYSCALL:
            return ERR_CMD_SIGN_TX_PARSE_INS_SYSCALL;
    }
    return ERR_BAD_STATE;  // should not happen.
}

static bool does_tokens_need_to_be_displayed(tokens_t *tokens, public_key_t *my_public_key) {
    if (tokens->owner.address_type != RE_ADDRESS_PUBLIC_KEY) {
        PRINTF("Owner of tokens should be of Radix Address type 'PUBLICKEY'\n");
        return false;
    }

    // We do not need to display tokens that are sent back to user (change).
    return !public_key_equals(&tokens->owner.public_key, my_public_key);
}

static bool does_substate_need_to_be_displayed(substate_t *substate, public_key_t *my_public_key) {
    switch (substate->type) {
        case SUBSTATE_TYPE_TOKENS:
            return does_tokens_need_to_be_displayed(&substate->tokens, my_public_key);
        case SUBSTATE_TYPE_PREPARED_STAKE:
            return true;
        case SUBSTATE_TYPE_PREPARED_UNSTAKE:
            return true;
        case SUBSTATE_TYPE_STAKE_OWNERSHIP:
        case SUBSTATE_TYPE_VALIDATOR_ALLOW_DELEGATION_FLAG:
        case SUBSTATE_TYPE_VALIDATOR_OWNER_COPY:
            return false;
    }

    return false;  // should never happen
}

bool does_instruction_need_to_be_displayed(re_instruction_t *instruction,
                                           public_key_t *my_public_key) {
    switch (instruction->ins_type) {
        case INS_END:
        case INS_DOWN:
        case INS_MSG:
        case INS_LDOWN:
        case INS_HEADER:
        case INS_VREAD:
        case INS_READ:
            return false;
        case INS_UP:
            return does_substate_need_to_be_displayed(&instruction->ins_up.substate, my_public_key);
        case INS_SYSCALL:
            // Stating `INS_SYSCALL` separatly so that I can write this comment:
            // SYSCALL contains the transaction fee. But since it comes amongst
            // the first bytes in the tx and we do not want to display the tx
            // fee amount now directly, but rather in the end as part of the
            // tx fee summary.
            return false;
    }

    return false;  // should not happen.
}