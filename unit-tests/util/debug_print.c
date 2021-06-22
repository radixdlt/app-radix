#include "debug_print.h"

#include "../../src/types/re_address.h"
#include "../../src/instruction/substate/prepared_stake.h"
#include "../../src/instruction/substate/prepared_unstake.h"
#include "../../src/instruction/substate/stake_share.h"
#include "../../src/instruction/substate/substate_id.h"

void dbg_print_re_ins_type(re_instruction_type_e ins_type) {
    print_message("Instruction type: ");
    switch (ins_type) {
        case INS_DOWN:
            print_message("'DOWN'");
            break;
        case INS_LDOWN:
            print_message("'LDOWN'");
            break;
        case INS_UP:
            print_message("'UP'");
            break;
        case INS_END:
            print_message("'END'");
            break;
        case INS_MSG:
            print_message("'MSG'");
            break;
        case INS_SYSCALL:
            print_message("'SYSCALL'");
            break;
        case INS_HEADER:
            print_message("'HEADER'");
            break;
        default:
            print_message("UNKNOWN instruction type: %d", ins_type);
            break;
    }
    print_message("\n");
}

// static void dbg_print_uint256(uint256_t *uint256) {
//     char amount[UINT256_DEC_STRING_MAX_LENGTH + 1] = {0};

//     if (!to_string_uint256(uint256, amount, sizeof(amount))) {
//         print_message("Failed to print uint256");
//         return;
//     }

//     print_message("%s\n", amount);
// }

// static void dbg_print_parse_tx_ins_state(parse_tx_ins_state_e state) {
//     print_message("Parse tx ins state: ");
//     switch (state) {
//         case STATE_PARSE_INS_READY_TO_PARSE:
//             print_message("'READY_TO_PARSE'");
//             break;
//         case STATE_PARSE_INS_PARSED_INSTRUCTION:
//             print_message("'PARSED_INSTRUCTION'");
//             break;
//         case STATE_PARSE_INS_NEEDS_APPROVAL:
//             print_message("'NEEDS_APPROVAL'");
//             break;
//         case STATE_PARSE_INS_APPROVED:
//             print_message("'APPROVED'");
//             break;
//         case STATE_PARSE_INS_FINISHED_PARSING_ALL_INS:
//             print_message("'FINISHED_PARSING_ALL_INS'");
//             break;
//         default:
//             print_message("UNKNOWN parse tx ins state: %d", state);
//             break;
//     }
//     print_message("\n");
// }

static void dbg_print_parse_address_failure_reason(parse_address_failure_reason_e failure_reason) {
    print_message("Parse address failure reason: ");
    switch (failure_reason) {
        case PARSE_ADDRESS_FAIL_HASHEDKEY_WRONG_LEN:
            print_message("'FAIL_HASHEDKEY_WRONG_LEN'");
            break;
        case PARSE_ADDRESS_FAIL_PUBKEY_WRONG_LEN:
            print_message("'FAIL_PUBKEY_WRONG_LEN'");
            break;
        case PARSE_ADDRESS_FAIL_UNRECOGNIZED_ADDRESS_TYPE:
            print_message("'FAIL_UNRECOGNIZED_ADDRESS_TYPE'");
            break;
        case PARSE_ADDRESS_FAIL_UNSUPPORTED_ADDRESS_TYPE:
            print_message("'UNSUPPORTED_ADDRESS_TYPE'");
            break;
    }
    print_message("\n");
}

static void dbg_print_parse_prepared_stake_outcome(parse_prepared_stake_outcome_t *outcome) {
    print_message("parse prepared stake outcome: ");
    switch (outcome->outcome_type) {
        case PARSE_PREPARED_STAKE_OK:
            print_message("'OK'");
            break;
        case PARSE_PREPARED_STAKE_FAILURE_PARSE_DELEGATE:
            print_message("'FAILURE_PARSE_DELEGATE'");
            break;
        case PARSE_PREPARED_STAKE_FAILURE_PARSE_OWNER:
            print_message("'FAILURE_PARSE_OWNER' - printing reason:\n");
            dbg_print_parse_address_failure_reason(outcome->parse_owner_failure);
            break;
        case PARSE_PREPARED_STAKE_FAILURE_PARSE_AMOUNT:
            print_message("'FAILURE_PARSE_AMOUNT'");
            break;
    }
    print_message("\n");
}

static void dbg_print_parse_prepared_unstake_outcome(parse_prepared_unstake_outcome_t *outcome) {
    print_message("parse prepared unstake outcome: ");
    switch (outcome->outcome_type) {
        case PARSE_PREPARED_UNSTAKE_OK:
            print_message("'OK'");
            break;
        case PARSE_PREPARED_UNSTAKE_FAILURE_PARSE_DELEGATE:
            print_message("'FAILURE_PARSE_DELEGATE'");
            break;
        case PARSE_PREPARED_UNSTAKE_FAILURE_PARSE_OWNER:
            print_message("'FAILURE_PARSE_OWNER' - printing reason:\n");
            dbg_print_parse_address_failure_reason(outcome->owner_parse_failure_reason);
            break;
        case PARSE_PREPARED_UNSTAKE_FAILURE_PARSE_AMOUNT:
            print_message("'FAILURE_PARSE_AMOUNT'");
            break;
    }
    print_message("\n");
}

static void dbg_print_parse_stake_share_outcome(parse_stake_share_outcome_t *outcome) {
    print_message("parse stake share outcome: ");
    switch (outcome->outcome_type) {
        case PARSE_STAKE_SHARE_OK:
            print_message("'OK'");
            break;
        case PARSE_STAKE_SHARE_FAILURE_PARSE_PUBLICKEY:
            print_message("'FAILURE_PARSE_PUBLICKEY'");
            break;
        case PARSE_STAKE_SHARE_FAILURE_PARSE_OWNER:
            print_message("'FAILURE_PARSE_OWNER' - printing reason:\n");
            dbg_print_parse_address_failure_reason(outcome->owner_parse_failure_reason);
            break;
        case PARSE_STAKE_SHARE_FAILURE_PARSE_AMOUNT:
            print_message("'FAILURE_PARSE_AMOUNT'");
            break;
    }
    print_message("\n");
}

static void dbg_print_parse_substate_id_outcome(parse_substate_id_outcome_e outcome) {
    print_message("Parse substate id outcome tpye:");
    switch (outcome) {
        case PARSE_SUBSTATE_ID_OK:
            print_message("'OK'");
            break;
        case PARSE_SUBSTATE_ID_FAILED_HASH:
            print_message("'FAILED_HASH'");
            break;
        case PARSE_SUBSTATE_ID_FAILED_INDEX:
            print_message("'FAILED_INDEX'");
            break;
    }
    print_message("\n");
}

// static void dbg_print_re_substate_type(re_substate_type_e substate_type) {
//     print_message("Substate type: ");
//     switch (substate_type) {
//         case SUBSTATE_TYPE_TOKENS:
//             print_message("'TOKENS'");
//             break;
//         case SUBSTATE_TYPE_PREPARED_STAKE:
//             print_message("'PREPARED_STAKE'");
//             break;
//         case SUBSTATE_TYPE_STAKE_SHARE:
//             print_message("'STAKE_SHARE'");
//             break;
//         case SUBSTATE_TYPE_PREPARED_UNSTAKE:
//             print_message("'PREPARED_UNSTAKE'");
//             break;
//         default:
//             print_message("UNKNOWN substate type: %d", substate_type);
//             break;
//     }
//     print_message("\n");
// }

static void dbg_print_parse_tokens_outcome(parse_tokens_outcome_t *outcome) {
    print_message("parse tokens outcome: ");
    switch (outcome->outcome_type) {
        case PARSE_TOKENS_OK:
            print_message("'OK'");
            break;
        case PARSE_TOKENS_FAILURE_PARSE_RRI:
            print_message("'FAILURE_PARSE_RRI' - printing reason:\n");
            dbg_print_parse_address_failure_reason(outcome->rri_parse_failure_reason);
            break;
        case PARSE_TOKENS_FAILURE_PARSE_OWNER:
            print_message("'FAILURE_PARSE_OWNER' - printing reason:\n");
            dbg_print_parse_address_failure_reason(outcome->owner_parse_failure_reason);
            break;
        case PARSE_TOKENS_FAILURE_PARSE_AMOUNT:
            print_message("'FAILURE_PARSE_AMOUNT'");
            break;
    }
    print_message("\n");
}

// static void dbg_print_re_address_type(re_address_type_e address_type) {
//     print_message("RE address type: ");
//     switch (address_type) {
//         case RE_ADDRESS_NATIVE_TOKEN:
//             print_message("'NATIVE_TOKEN'");
//             break;
//         case RE_ADDRESS_HASHED_KEY_NONCE:
//             print_message("'HASHED_KEY_NONCE'");
//             break;
//         case RE_ADDRESS_PUBLIC_KEY:
//             print_message("'PUBLIC_KEY'");
//             break;
//     }
//     print_message("\n");
// }

static void dbg_print_parse_bytes_outcome(parse_bytes_outcome_e outcome) {
    print_message("parse_bytes_outcome\n");
    switch (outcome) {
        case PARSE_BYTES_OK:
            print_message("'OK'");
            break;
        case PARSE_BYTES_FAILED_TO_PARSE_LENGTH:
            print_message("'FAILED_TO_PARSE_LENGTH'");
            break;
        case PARSE_BYTES_FAIL_WRONG_LENGTH:
            print_message("'FAIL_WRONG_LENGTH'");
            break;
    }
    print_message("\n");
}

static void dbg_print_parse_substate_outcome(parse_substate_outcome_t *failure_reason) {
    print_message("parse substate outcome: \n");
    switch (failure_reason->outcome_type) {
        case PARSE_SUBSTATE_OK:
            print_message("'OK'");
            break;
        case PARSE_SUBSTATE_FAIL_UNRECOGNIZED_SUBSTATE_TYPE:
            print_message("'FAIL_UNRECOGNIZED_SUBSTATE_TYPE': %hu",
                          failure_reason->unrecognized_substate_type_value);
            break;
        case PARSE_SUBSTATE_FAIL_UNSUPPORTED_SUBSTATE_TYPE:
            print_message("'FAIL_UNSUPPORTED_SUBSTATE_TYPE': %hu",
                          failure_reason->unsupported_substate_type_value);
            break;
        case PARSE_SUBSTATE_FAILED_TO_PARSE_TOKENS:
            print_message("'FAILED_TO_PARSE_TOKENS' - printing reason:\n");
            dbg_print_parse_tokens_outcome(&failure_reason->tokens_failure);
            break;
        case PARSE_SUBSTATE_FAILED_TO_PARSE_PREPARED_STAKE:
            print_message("'FAILED_TO_PARSE_PREPARED_STAKE' - printing reason:\n");
            dbg_print_parse_prepared_stake_outcome(&failure_reason->prepared_stake_failure);
            break;
        case PARSE_SUBSTATE_FAILED_TO_PARSE_PREPARED_UNSTAKE:
            print_message("'FAILED_TO_PARSE_PREPARED_UNSTAKE' - printing reason:\n");
            dbg_print_parse_prepared_unstake_outcome(&failure_reason->prepared_unstake_failure);
            break;
        case PARSE_SUBSTATE_FAILED_TO_PARSE_SHARE_STAKE:
            print_message("'FAILED_TO_PARSE_SHARE_STAKE' - printing reason:\n");
            dbg_print_parse_stake_share_outcome(&failure_reason->stake_share_failure);
            break;
    }
    print_message("\n");
}

static void dbg_print_parse_instruction_outcome(parse_instruction_outcome_t *outcome) {
    print_message("Parse instruction type: ");
    switch (outcome->outcome_type) {
        case PARSE_INS_OK:
            print_message("'OK'");
            break;
        case PARSE_INS_FAIL_UNREGOZNIED_INSTRUCTION_TYPE:
            print_message("'FAIL_UNREGOZNIED_INSTRUCTION_TYPE'");
            break;
        case PARSE_INS_FAIL_UNSUPPORTED_INSTRUCTION_TYPE:
            print_message("'FAIL_UNSUPPORTED_INSTRUCTION_TYPE'");
            break;
        case PARSE_INS_FAILED_TO_PARSE_SUBSTATE:
            print_message("'FAILED_TO_PARSE_SUBSTATE' - printing reason:\n");
            dbg_print_parse_substate_outcome(&outcome->substate_failure);
            break;
        case PARSE_INS_FAILED_TO_PARSE_SUBSTATE_ID:
            print_message("'FAILED_TO_PARSE_SUBSTATE_ID' - printing reason:\n");
            dbg_print_parse_substate_id_outcome(outcome->substate_id_failure);
            break;
        case PARSE_INS_FAILED_TO_PARSE_SUBSTATE_INDEX:
            print_message("'FAILED_TO_PARSE_SUBSTATE_INDEX'");
            break;
        case PARSE_INS_FAILED_TO_PARSE_MSG:
            print_message("'FAILED_TO_PARSE_MSG' - printing reason:\n");
            dbg_print_parse_bytes_outcome(outcome->message_failure);
            break;
        case PARSE_INS_FAILED_TO_PARSE_HEADER:
            print_message("'FAILED_TO_PARSE_HEADER'");
            break;
        case PARSE_INS_INVALID_HEADER:
            print_message("'INVALID_HEADER'");
            break;
        case PARSE_INS_FAILED_TO_PARSE_SYSCALL:
            print_message("'FAILED_TO_PARSE_SYSCALL' - printing reason:\n");
            dbg_print_parse_bytes_outcome(outcome->syscall_failure);
            break;
    }
    print_message("\n");
}

void dbg_print_parse_process_instruction_outcome(parse_and_process_instruction_outcome_t *outcome) {
    print_message("Parse and process instruction outcome: ");
    switch (outcome->outcome_type) {
        case PARSE_PROCESS_INS_SUCCESS_FINISHED_PARSING_INS:
            print_message("'SUCCESS_FINISHED_PARSING_INS'");
            break;
        case PARSE_PROCESS_INS_SUCCESS_FINISHED_PARSING_WHOLE_TRANSACTION:
            print_message("'SUCCESS_FINISHED_PARSING_WHOLE_TRANSACTION'");
            break;
        case PARSE_PROCESS_INS_BAD_STATE:
            print_message("'BAD_STATE'");
            break;
        case PARSE_PROCESS_INS_BYTE_COUNT_MISMATCH:
            print_message("'BYTE_COUNT_MISMATCH'");
            break;
        case PARSE_PROCESS_INS_DISABLE_MINT_AND_BURN_FLAG_NOT_SET:
            print_message("'DISABLE_MINT_AND_BURN_FLAG_NOT_SET'");
            break;
        case PARSE_PROCESS_INS_PARSE_TX_FEE_FROM_SYSCALL_FAIL:
            print_message("'PARSE_TX_FEE_FROM_SYSCALL_FAIL'");
            break;
        case PARSE_PROCESS_INS_TX_DOES_NOT_CONTAIN_TX_FEE:
            print_message("'TX_DOES_NOT_CONTAIN_TX_FEE'");
            break;
        case PARSE_PROCESS_INS_LAST_INS_WAS_NOT_INS_END:
            print_message("'LAST_INS_WAS_NOT_INS_END'");
            break;
        case PARSE_PROCESS_INS_FAILED_TO_PARSE:
            print_message("'FAILED_TO_PARSE' - printing reason:\n");
            dbg_print_parse_instruction_outcome(&outcome->parse_failure);
            break;
        default:
            print_message("UNKNOWN Parse and process instruction outcome type: %d",
                          outcome->outcome_type);
            break;
    }
    print_message("\n");
}
