#include "transaction_parser.h"

#include <string.h>     // explicit_bzero
#include "../crypto.h"  // update_hash

status_word_t status_word_for_parse_and_process_ins_failure(
    parse_and_process_instruction_outcome_t *failure) {
    switch (failure->outcome_type) {
        case PARSE_PROCESS_INS_SUCCESS_FINISHED_PARSING_INS:
        case PARSE_PROCESS_INS_SUCCESS_FINISHED_PARSING_WHOLE_TRANSACTION:
            THROW(ERR_BAD_STATE);  // Did not expect success.
        case PARSE_PROCESS_INS_BAD_STATE:
            return ERR_BAD_STATE;
        case PARSE_PROCESS_INS_BYTE_COUNT_MISMATCH:
            return ERR_CMD_SIGN_TX_PARSE_TX_SIZE_FAILURE;
        case PARSE_PROCESS_INS_DISABLE_MINT_AND_BURN_FLAG_NOT_SET:
            return ERR_CMD_SIGN_TX_DISABLE_MINT_AND_BURN_FLAG_NOT_SET;
        case PARSE_PROCESS_INS_PARSE_TX_FEE_FROM_SYSCALL_FAIL:
            return ERR_CMD_SIGN_TX_PARSE_TX_FEE_FROM_SYSCALL_FAIL;
        case PARSE_PROCESS_INS_LAST_INS_WAS_NOT_INS_END:
            return ERR_CMD_SIGN_TX_LAST_INSTRUCTION_WAS_NOT_INS_END;
        case PARSE_PROCESS_INS_FAILED_TO_PARSE:
            return status_word_for_failed_to_parse_ins(&failure->parse_failure);
    }
}
void print_parse_process_instruction_outcome(parse_and_process_instruction_outcome_t *outcome) {
    PRINTF("Parse and process instruction outcome: ");
    switch (outcome->outcome_type) {
        case PARSE_PROCESS_INS_SUCCESS_FINISHED_PARSING_INS:
            PRINTF("'SUCCESS_FINISHED_PARSING_INS'");
            break;
        case PARSE_PROCESS_INS_SUCCESS_FINISHED_PARSING_WHOLE_TRANSACTION:
            PRINTF("'SUCCESS_FINISHED_PARSING_WHOLE_TRANSACTION'");
            break;
        case PARSE_PROCESS_INS_BAD_STATE:
            PRINTF("'BAD_STATE'");
            break;
        case PARSE_PROCESS_INS_BYTE_COUNT_MISMATCH:
            PRINTF("'BYTE_COUNT_MISMATCH'");
            break;
        case PARSE_PROCESS_INS_DISABLE_MINT_AND_BURN_FLAG_NOT_SET:
            PRINTF("'DISABLE_MINT_AND_BURN_FLAG_NOT_SET'");
            break;
        case PARSE_PROCESS_INS_PARSE_TX_FEE_FROM_SYSCALL_FAIL:
            PRINTF("'PARSE_TX_FEE_FROM_SYSCALL_FAIL'");
            break;
        case PARSE_PROCESS_INS_LAST_INS_WAS_NOT_INS_END:
            PRINTF("'LAST_INS_WAS_NOT_INS_END'");
            break;
        case PARSE_PROCESS_INS_FAILED_TO_PARSE:
            PRINTF("'FAILED_TO_PARSE' - printing reason:\n");
            print_parse_instruction_outcome(&outcome->parse_failure);
            break;
        default:
            PRINTF("UNKNOWN Parse and process instruction outcome type: %d", outcome->outcome_type);
            break;
    }
    PRINTF("\n");
}

bool parse_tx_fee_from_syscall(re_ins_syscall_t *syscall, uint256_t *tx_fee) {
    PRINTF("Length of SYSCALL data: %d.\n", syscall->call_data.length);
    PRINTF("SYSCALL data: %.*H.\n", syscall->call_data.length, syscall->call_data.data);

    if (syscall->call_data.length != 33) {
        PRINTF(
            "Failed to parse tx fee from syscall, wrong length, requiring length of 33, but got: "
            "%d.\n",
            syscall->call_data.length);
        return false;
    }
    uint8_t required_tx_fee_version_byte = 0x00;
    if (syscall->call_data.data[0] != required_tx_fee_version_byte) {
        PRINTF(
            "Failed to parse tx fee from syscall, incorrect version byte, required: %d, but got: "
            "%d.\n",
            required_tx_fee_version_byte,
            syscall->call_data.data[0]);
        return false;
    }

    readu256BE(syscall->call_data.data + 1, tx_fee);

    return true;
}

bool parse_and_process_instruction_from_buffer(buffer_t *buffer,
                                               transaction_parser_t *tx_parser,
                                               parse_and_process_instruction_outcome_t *outcome) {
    instruction_parser_t *instruction_parser = &tx_parser->instruction_parser;

    // Important to reset memory between subsequent instructions.
    explicit_bzero(&instruction_parser->instruction, sizeof(instruction_parser->instruction));

    // Parse transaction: incoming Radix Engine instructions, one at a time.
    if (instruction_parser->state != STATE_PARSE_INS_READY_TO_PARSE) {
        outcome->outcome_type = PARSE_PROCESS_INS_BAD_STATE;
        return false;
    }

    tx_parser->config.transaction_metadata.tx_bytes_received_count += buffer->size;
    if (tx_parser->config.transaction_metadata.tx_bytes_received_count >
        tx_parser->config.transaction_metadata.tx_byte_count) {
        outcome->outcome_type = PARSE_PROCESS_INS_BYTE_COUNT_MISMATCH;
        return false;
    }

    // Parse newly recieved single Radix Engine instruction
    if (!parse_instruction(buffer, &outcome->parse_failure, &instruction_parser->instruction)) {
        outcome->outcome_type = PARSE_PROCESS_INS_FAILED_TO_PARSE;
        return false;
    }

    tx_parser->config.transaction_metadata.number_of_instructions_received += 1;

    if (instruction_parser->instruction.ins_type == INS_HEADER) {
        bool mint_and_burn_is_forbidden = instruction_parser->instruction.ins_header.flag ==
                                          INS_HEADER_FLAG_DISALLOWING_TOKEN_BURN_AND_TOKEN_MINT;
        tx_parser->transaction.have_asserted_no_mint_or_burn = mint_and_burn_is_forbidden;
    }

    // Just finished parsing an instruction that was not INS_HEADER
    if (!tx_parser->transaction.have_asserted_no_mint_or_burn) {
        // ☠️  ILLEGAL TX: might burn/mint tokens ☠️
        outcome->outcome_type = PARSE_PROCESS_INS_DISABLE_MINT_AND_BURN_FLAG_NOT_SET;
        return false;
    }

    // If instruction is SYSCALL, parse out bytes as transaction fee.
    if (instruction_parser->instruction.ins_type == INS_SYSCALL) {
        if (!parse_tx_fee_from_syscall(&instruction_parser->instruction.ins_syscall,
                                       &tx_parser->transaction.tx_fee)) {
            outcome->outcome_type = PARSE_PROCESS_INS_PARSE_TX_FEE_FROM_SYSCALL_FAIL;
            return false;
        }

        // Add tx fee to total cost
        add256(&tx_parser->transaction.tx_fee,
               &tx_parser->transaction.total_xrd_amount_incl_fee,
               &tx_parser->transaction.total_xrd_amount_incl_fee);
    }

    if (instruction_parser->instruction.ins_up.substate.type == SUBSTATE_TYPE_TOKENS) {
        // My public key matches owner of tokens
        bool token_amount_is_change_back_to_me = public_key_equals(
            &tx_parser->signing.my_derived_public_key.address.public_key,
            &instruction_parser->instruction.ins_up.substate.tokens.owner.public_key);

        // I own the tokens and the rri matches XRD
        bool increment_xrd_grand_total =
            !token_amount_is_change_back_to_me &&
            instruction_parser->instruction.ins_up.substate.tokens.rri.address_type ==
                RE_ADDRESS_NATIVE_TOKEN;

        if (increment_xrd_grand_total) {
            // Spending XRD => increment total XRD spent counter
            add256(&instruction_parser->instruction.ins_up.substate.tokens.amount,
                   &tx_parser->transaction.total_xrd_amount_incl_fee,
                   &tx_parser->transaction.total_xrd_amount_incl_fee);
        }
    }

    bool was_last_apdu = tx_parser->config.transaction_metadata.number_of_instructions_received ==
                         tx_parser->config.transaction_metadata.total_number_of_instructions;

    // Update the hash
    update_hash(&tx_parser->hasher,
                buffer->ptr,
                buffer->size,
                was_last_apdu,
                tx_parser->signing.digest,
                HASH_LEN);

    if (was_last_apdu) {
        if (tx_parser->config.transaction_metadata.tx_bytes_received_count !=
            tx_parser->config.transaction_metadata.tx_byte_count) {
            outcome->outcome_type = PARSE_PROCESS_INS_BYTE_COUNT_MISMATCH;
            return false;
        }

        // G_parse_tx_state_finished_parsing_all();
        if (instruction_parser->instruction.ins_type != INS_END) {
            // return io_send_sw(ERR_CMD_SIGN_TX_LAST_INSTRUCTION_WAS_NOT_INS_END);
            outcome->outcome_type = PARSE_PROCESS_INS_LAST_INS_WAS_NOT_INS_END;
            return false;
        }

        // if (!tx_parser->config.parsed_instruction_display_config.display_tx_summary) {
        //     PRINTF(
        //         "You have specified to skip displaying TX summary UI => sign tx hash "
        //         "immediately.\n");
        //     if (!crypto_sign_message(&tx_parser->signing)) {
        //         // G_context.state = STATE_NONE;
        //         // return io_send_sw(ERR_CMD_SIGN_TX_ECDSA_SIGN_FAIL);

        //         return false;
        //     } else {
        //         // return helper_send_response_signature(
        //         //     true,
        //         //     &tx_parser->signing);  // also respond with `hash`: true
        //           outcome->outcome_type =
        //           PARSE_PROCESS_INS_OK_FINISHED_WITH_WHOLE_TX_SKIP_DISPLAY_BECAUSE_IN_TEST;
        //         return true;
        //     }
        // }

        // return ui_display_tx_summary(&tx_parser->transaction,
        //                              &tx_parser->signing.my_derived_public_key.bip32_path,
        //                              tx_parser->signing.digest);
        outcome->outcome_type =
            PARSE_PROCESS_INS_SUCCESS_FINISHED_PARSING_WHOLE_TRANSACTION;  //_DISPLAY_TX_SUMMARY;
        return true;

    } else {
        // // G_parse_tx_state_did_parse_new();

        // // Not done yet => tell host machine to continue sending next RE instruction.
        // if (does_instruction_need_to_be_displayed(
        //         &instruction_parser->instruction,
        //         &tx_parser->signing.my_derived_public_key.address.public_key) &&
        //     tx_parser->config.parsed_instruction_display_config.display_substate_contents) {
        //     // G_parse_tx_state_ins_needs_approval();

        //     // return ui_display_instruction(&instruction_parser->instruction);

        //     outcome->outcome_type = PARSE_PROCESS_INS_OK_DISPLAY_INS_BEFORE_PROCEEDING_WITH_NEXT;
        //     return true;
        // }

        // G_parse_tx_state_ready_to_parse();

        outcome->outcome_type =
            PARSE_PROCESS_INS_SUCCESS_FINISHED_PARSING_INS;  //_PROCEED_WITH_NEXT_INS;
        return true;
    }
}