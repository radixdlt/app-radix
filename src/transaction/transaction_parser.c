#include "transaction_parser.h"

#include <string.h>  // explicit_bzero

#include "../types/uint256.h"
#include "../types/public_key.h"

#include "../bridge.h"

#include "../instruction/instruction.h"  // re_ins_syscall_t

status_word_t status_word_for_parse_and_process_ins_failure(
    parse_and_process_instruction_outcome_t *failure) {
    switch (failure->outcome_type) {
        case PARSE_PROCESS_INS_SUCCESS_FINISHED_PARSING_INS:
        case PARSE_PROCESS_INS_SUCCESS_FINISHED_PARSING_WHOLE_TRANSACTION:
            // THROW(ERR_BAD_STATE);  // Did not expect success.
            return ERR_BAD_STATE;
        case PARSE_PROCESS_INS_BAD_STATE:
            return ERR_BAD_STATE;
        case PARSE_PROCESS_INS_BYTE_COUNT_MISMATCH:
            return ERR_CMD_SIGN_TX_PARSE_TX_SIZE_FAILURE;
        case PARSE_PROCESS_INS_DISABLE_MINT_AND_BURN_FLAG_NOT_SET:
            return ERR_CMD_SIGN_TX_DISABLE_MINT_AND_BURN_FLAG_NOT_SET;
        case PARSE_PROCESS_INS_PARSE_TX_FEE_FROM_SYSCALL_FAIL:
            return ERR_CMD_SIGN_TX_PARSE_TX_FEE_FROM_SYSCALL_FAIL;
        case PARSE_PROCESS_INS_TX_DOES_NOT_CONTAIN_TX_FEE:
            return ERR_CMD_SIGN_TX_TX_DID_NOT_CONTAIN_TX_FEE;
        case PARSE_PROCESS_INS_FAILED_TO_PARSE:
            return status_word_for_failed_to_parse_ins(&failure->parse_failure);
    }

    return ERR_BAD_STATE;  // should never happen
}

/**
 * @brief Parse transaction fee from SYSCALL instruction.
 *
 * @param syscall A syscall instruction to parse from.
 * @param tx_fee target uint256 to put result of parsing in
 * @return true if successful
 * @return false if fail
 */
bool parse_tx_fee_from_syscall(re_ins_syscall_t *syscall, uint256_t *tx_fee) {
    if (syscall->call_data.length != 33) {
        return false;
    }

    if (syscall->call_data.data[0] != INS_SYSCALL_TX_FEE_RESERVE_PUT &&
        syscall->call_data.data[0] != INS_SYSCALL_TX_FEE_RESERVE_TAKE) {
        // Only these two values above are known to relate to TX fee.
        return false;
    }

    readu256BE(syscall->call_data.data + 1, tx_fee);

    return true;
}

/*
 * Tx fee is calculated like so:
 * Also a new syscall was added `FEE_RESERVE_TAKE (0x01)`, apart from old `FEE_RESERVE_PUT (0x00)`
 * to be able to claim back unused fees in the fee reserve. A general user transaction will look
 * like:
 *
 * DOWN <substate_id>
 * SYSCALL FEE_RESERVE_PUT <put_amt>
 * ...
 * SYSCALL FEE_RESERVE_TAKE <take_amt0>
 * ...
 * SYSCALL FEE_RESERVE_TAKE <take_amt1>
 * END
 * SIG <signature>
 *
 * The corresponding fee paid in the transaction is then:
 * `fee_paid = put_amt - sum(take_amt*)`
 *
 * There should only be one and only one `put_amt` value. There may be 0 or more `take_amt` values.
 *
 */
static bool update_tx_fee_and_total_xrd_cost_if_needed(re_ins_syscall_t *syscall,
                                                       transaction_t *transaction) {
    bool sys_call_is_tx_fee_put =
        (bool) syscall->call_data.data[0] == INS_SYSCALL_TX_FEE_RESERVE_PUT;
    bool sys_call_is_tx_fee_take =
        (bool) syscall->call_data.data[0] == INS_SYSCALL_TX_FEE_RESERVE_TAKE;

    if (!sys_call_is_tx_fee_put && !sys_call_is_tx_fee_take) {
        return true;
    }

    // SYSCALL specifies TX fee
    uint256_t amount;
    if (!parse_tx_fee_from_syscall(syscall, &amount)) {
        return false;
    }

    if (sys_call_is_tx_fee_put) {
        if (is_tx_fee_set(transaction)) {
            // Invalid state, a transaction must not specify more than one SYSCALL with
            // `TX_FEE_RESERVE_PUT`.
            return false;
        }

        // Copy over tx fee.
        copy256(&transaction->tx_fee, &amount);

        // Add tx fee to total cost
        add256(&amount,
               &transaction->total_xrd_amount_incl_fee,
               &transaction->total_xrd_amount_incl_fee);
    } else if (sys_call_is_tx_fee_take) {
        if (!is_tx_fee_set(transaction)) {
            // Invalid state, a transaction must first specify one (and only one) SYSCALL
            // with `TX_FEE_RESERVE_PUT` before it specifies SYSCALLs with
            // `INS_SYSCALL_TX_FEE_RESERVE_TAKE`. We just parsed a `TX_FEE_RESERVE_TAKE`,
            // but tx fee is zero, meaning we did not earlier parse `TX_FEE_RESERVE_PUT`.
            return false;
        }

        if (gt256(&amount, &transaction->tx_fee) ||
            gt256(&amount, &transaction->total_xrd_amount_incl_fee)) {
            // Invalid state, just parsed a `TX_FEE_RESERVE_TAKE` which was larger than
            // amount left from put. This would result in a negative tx fee.
            return false;
        }

        // TX_FEE = TX_FEE - TX_FEE_RESERVE_TAKE
        minus256(&transaction->tx_fee, &amount, &transaction->tx_fee);

        // TOTAL_XRD_COST = TOTAL_XRD_COST - TX_FEE_RESERVE_TAKE
        minus256(&transaction->total_xrd_amount_incl_fee,
                 &amount,
                 &transaction->total_xrd_amount_incl_fee);
    }

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

    transaction_metadata_t *tx_metadata = &tx_parser->transaction_metadata;

    tx_metadata->tx_bytes_received_count += buffer->size;
    if (tx_metadata->tx_bytes_received_count > tx_metadata->tx_byte_count) {
        outcome->outcome_type = PARSE_PROCESS_INS_BYTE_COUNT_MISMATCH;
        return false;
    }

    // Parse newly recieved single Radix Engine instruction
    if (!parse_instruction(buffer, &outcome->parse_failure, &instruction_parser->instruction)) {
        outcome->outcome_type = PARSE_PROCESS_INS_FAILED_TO_PARSE;
        return false;
    }

    tx_metadata->number_of_instructions_received += 1;

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
        if (!update_tx_fee_and_total_xrd_cost_if_needed(
                &instruction_parser->instruction.ins_syscall,
                &tx_parser->transaction)) {
            outcome->outcome_type = PARSE_PROCESS_INS_PARSE_TX_FEE_FROM_SYSCALL_FAIL;
            return false;
        }
    }

    if (instruction_parser->instruction.ins_up.substate.type == SUBSTATE_TYPE_TOKENS) {
        // My public key matches owner of tokens
        bool token_amount_is_change_back_to_me = public_key_equals(
            &tx_parser->signing.my_derived_public_key.address.public_key,
            &instruction_parser->instruction.ins_up.substate.tokens.owner.public_key);

        // I own the tokens and the rri matches XRD
        bool increment_xrd_grand_total =
            !token_amount_is_change_back_to_me &&
            instruction_parser->instruction.ins_up.substate.tokens.resource.address_type ==
                RE_ADDRESS_NATIVE_TOKEN;

        if (increment_xrd_grand_total) {
            // Spending XRD => increment total XRD spent counter
            add256(&instruction_parser->instruction.ins_up.substate.tokens.amount,
                   &tx_parser->transaction.total_xrd_amount_incl_fee,
                   &tx_parser->transaction.total_xrd_amount_incl_fee);
        }
    }

    bool was_last_apdu =
        tx_metadata->number_of_instructions_received == tx_metadata->total_number_of_instructions;

    bool finalize_hash = was_last_apdu;

    // Update the hash, finalize if needed
    update_hash_twice(&tx_parser->signing.hasher, buffer, finalize_hash);

    if (was_last_apdu) {
        if (!is_tx_fee_set(&tx_parser->transaction)) {
            outcome->outcome_type = PARSE_PROCESS_INS_TX_DOES_NOT_CONTAIN_TX_FEE;
            return false;
        }

        if (tx_metadata->tx_bytes_received_count != tx_metadata->tx_byte_count) {
            outcome->outcome_type = PARSE_PROCESS_INS_BYTE_COUNT_MISMATCH;
            return false;
        }

        outcome->outcome_type = PARSE_PROCESS_INS_SUCCESS_FINISHED_PARSING_WHOLE_TRANSACTION;
        return true;
    } else {
        outcome->outcome_type = PARSE_PROCESS_INS_SUCCESS_FINISHED_PARSING_INS;
        return true;
    }
}

static bool validate_tx_parser_config_tx_metadata(transaction_metadata_t *metadata) {
    if (metadata->tx_byte_count < 1) {
        // Must have at at least one byte to sign.
        PRINTF("Invalid Tx Parser Config MetaData: TX byte count.\n");
        return false;
    }
    if (metadata->tx_bytes_received_count != 0) {
        // Must start at 0
        PRINTF("Invalid Tx Parser Config MetaData: TX recieved byte count.\n");
        return false;
    }

    if (metadata->total_number_of_instructions < 1) {
        // Must have at least one instruction to sign.
        PRINTF("Invalid Tx Parser Config MetaData: instruction count.\n");
        return false;
    }
    if (metadata->number_of_instructions_received != 0) {
        // Must start at 0
        PRINTF("Invalid Tx Parser Config MetaData: received instruction count.\n");
        return false;
    }

    return true;
}

static void setup_instruction_parser(instruction_parser_t *ins_parser) {
    // Setup state
    ins_parser->state = STATE_PARSE_INS_READY_TO_PARSE;
}

bool init_tx_parser_with_config(transaction_parser_t *tx_parser,
                                derive_my_pubkey_key_fn derive_my_pubkey,
                                sha_256_once_fn sha_256_once,
                                init_implementing_hasher_fn reinit_implementing_hasher,
                                init_transaction_parser_config_t *config,
                                init_tx_parser_outcome_t *outcome) {
    if (!validate_tx_parser_config_tx_metadata(&config->transaction_metadata)) {
        outcome->outcome_type = INIT_TX_PARSER_INVALID_TX_METADATA_IN_CONFIG;
        return false;
    }

    // Copy over `transaction_metadata` from `config`
    memmove(&tx_parser->transaction_metadata,
            &config->transaction_metadata,
            sizeof(config->transaction_metadata));

    // Copy over `instruction_display_config` from `config`
    memmove(&tx_parser->instruction_display_config,
            &config->instruction_display_config,
            sizeof(config->instruction_display_config));

    // Copy over `bip32_path` from `config`
    memmove(&tx_parser->signing.my_derived_public_key.bip32_path,
            &config->bip32_path,
            sizeof(config->bip32_path));

    // Need our public key to compare against recipient addresses in transfer/stake to identify
    // spent amount and amounts being change back to ourselves
    if (!derive_my_pubkey(&tx_parser->signing.my_derived_public_key)) {
        outcome->outcome_type = INIT_TX_PARSER_FAILED_TO_DERIVE_MY_PUBLIC_KEY;
        return false;
    }

    // Setup hasher
    init_hasher(&tx_parser->signing.hasher, sha_256_once, reinit_implementing_hasher);

    // Setup instruction parser
    setup_instruction_parser(&tx_parser->instruction_parser);

    return true;
}