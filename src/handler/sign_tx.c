/*****************************************************************************
 *   Ledger App Radix.
 *   (c) 2020 Ledger SAS.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *****************************************************************************/

#include <stdint.h>   // uint*_t
#include <stdbool.h>  // bool
#include <stddef.h>   // size_t
#include <string.h>   // memset, explicit_bzero

#include "os.h"
#include "cx.h"

#include "sign_tx.h"

#include "../state.h"
#include "../sw.h"
#include "../globals.h"
#include "../crypto.h"
#include "../ui/display.h"
#include "../types/buffer.h"
#include "../instruction/instruction.h"
#include "../common/bech32_encode.h"
#include "../helper/send_response.h"
#include "../common/read.h"    // read_u16_be, read_u32_be
#include "../common/format.h"  // print_uint256

/**
 * @brief Parse transaction fee from SYSCALL instruction.
 *
 * When SYSCALL is used for tx fee, it MUST have length 33, and the first byte (a version byte),
 * MUST be 0x00, and the remaining 32 bytes should be parsed as a UInt256.
 *
 * @param syscall A syscall instruction to parse from.
 * @param tx_fee target uint256 to put result of parsing in
 * @return true if successful
 * @return false if fail
 */
static int parse_tx_fee_from_syscall(re_ins_syscall_t *syscall, uint256_t *tx_fee) {
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

static int parse_and_process_instruction_from_buffer(buffer_t *buffer,
                                                     transaction_parser_t *tx_parser) {
    instruction_parser_t *instruction_parser =
        &G_context.sign_tx_info.transaction_parser.instruction_parser;

    // Important to reset memory between subsequent instructions.
    explicit_bzero(&instruction_parser->instruction, sizeof(instruction_parser->instruction));

    // Parse transaction: incoming Radix Engine instructions, one at a time.
    if (G_context.req_type != CONFIRM_TRANSACTION || G_context.state != STATE_NONE ||
        instruction_parser->state != STATE_PARSE_INS_READY_TO_PARSE) {
        return io_send_sw(ERR_BAD_STATE);
    }

    tx_parser->config.transaction_metadata.tx_bytes_received_count += buffer->size;
    if (tx_parser->config.transaction_metadata.tx_bytes_received_count >
        tx_parser->config.transaction_metadata.tx_byte_count) {
        PRINTF("Received more bytes than size of transaction. Bad state => abort signing of tx.");
        return io_send_sw(ERR_BAD_STATE);
    }

    // Parse newly recieved single Radix Engine instruction
    parse_instruction_outcome_t ins_result;
    if (!parse_instruction(buffer, &ins_result, &instruction_parser->instruction)) {
        PRINTF("Failed to parse instruction\n");
        uint16_t sw = status_word_for_failed_to_parse_ins(&ins_result);
        return io_send_sw(sw);
    }

    tx_parser->config.transaction_metadata.number_of_instructions_received += 1;

    PRINTF("Finished parsing instruction, have now parsed: %d/%d instructions.\n",
           tx_parser->config.transaction_metadata.number_of_instructions_received,
           tx_parser->config.transaction_metadata.total_number_of_instructions);

    if (instruction_parser->instruction.ins_type == INS_HEADER) {
        bool mint_and_burn_is_forbidden = instruction_parser->instruction.ins_header.flag ==
                                          INS_HEADER_FLAG_DISALLOWING_TOKEN_BURN_AND_TOKEN_MINT;
        tx_parser->transaction.have_asserted_no_mint_or_burn = mint_and_burn_is_forbidden;
    } else {
        // Just finished parsing an instruction that was not INS_HEADER
        if (!tx_parser->transaction.have_asserted_no_mint_or_burn) {
            // ☠️  ILLEGAL TX: might burn/mint tokens ☠️
            PRINTF(
                "TX might contain burning or minting of new tokens, but we cannot parse this. This "
                "is considered a fatal error and we abort parsing this tx now, and return an "
                "error.\n");
            return io_send_sw(ERR_CMD_SIGN_TX_DISABLE_MINT_AND_BURN_FLAG_NOT_SET);
        }
    }

    // If instruction is SYSCALL, parse out bytes as transaction fee.
    if (instruction_parser->instruction.ins_type == INS_SYSCALL) {
        PRINTF("Parsing tx fee from SYSCALL.\n");

        if (!parse_tx_fee_from_syscall(&instruction_parser->instruction.ins_syscall,
                                       &tx_parser->transaction.tx_fee)) {
            PRINTF("Failed to parse tx fee from SYSCALL.\n");
            return io_send_sw(ERR_CMD_SIGN_TX_PARSE_TX_FEE_FROM_SYSCALL_FAIL);
        }

        PRINTF("Successfully parsed tx fee:");
        print_uint256(&tx_parser->transaction.tx_fee);
        PRINTF("\n");

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
            PRINTF("Spending XRD in tokens transfer, will add to total cost:");
            print_uint256(&instruction_parser->instruction.ins_up.substate.tokens.amount);
            PRINTF("\n");

            // Spending XRD => increment total XRD spent counter
            add256(&instruction_parser->instruction.ins_up.substate.tokens.amount,
                   &tx_parser->transaction.total_xrd_amount_incl_fee,
                   &tx_parser->transaction.total_xrd_amount_incl_fee);
        }
    }

    bool was_last_apdu = tx_parser->config.transaction_metadata.number_of_instructions_received ==
                         tx_parser->config.transaction_metadata.total_number_of_instructions;

    if (was_last_apdu) {
        if (tx_parser->config.transaction_metadata.tx_bytes_received_count !=
            tx_parser->config.transaction_metadata.tx_byte_count) {
            PRINTF(
                "Number of received bytes does not match number of expected bytes. Bad state => "
                "abort signing of tx. received count: %d, and tx have size: %d\n",
                tx_parser->config.transaction_metadata.tx_bytes_received_count,
                tx_parser->config.transaction_metadata.tx_byte_count);
            return io_send_sw(ERR_BAD_STATE);
        }

        PRINTF("Finished parsing all instructions.\n");
        G_context.state = STATE_PARSED;
    }

    // Update the hash
    update_hash(&tx_parser->hasher,
                buffer->ptr,
                buffer->size,
                was_last_apdu,
                tx_parser->signing.digest,
                HASH_LEN);

    if (was_last_apdu) {
        G_parse_tx_state_finished_parsing_all();
        if (instruction_parser->instruction.ins_type != INS_END) {
            PRINTF("Expected last instruction to be 'INS_END' but it was not => abort tx signing.");
            return io_send_sw(ERR_CMD_SIGN_TX_LAST_INSTRUCTION_WAS_NOT_INS_END);
        }

        PRINTF("Finished parsing all instruction.\n");

        if (!tx_parser->config.parsed_instruction_display_config.display_tx_summary) {
            PRINTF(
                "You have specified to skip displaying TX summary UI => sign tx hash "
                "immediately.\n");
            if (!crypto_sign_message(&tx_parser->signing)) {
                G_context.state = STATE_NONE;
                return io_send_sw(ERR_CMD_SIGN_TX_ECDSA_SIGN_FAIL);
            } else {
                return helper_send_response_signature(
                    true,
                    &tx_parser->signing);  // also respond with `hash`: true
            }
        }

        return ui_display_tx_summary(&tx_parser->transaction,
                                     &tx_parser->signing.my_derived_public_key.bip32_path,
                                     tx_parser->signing.digest);

    } else {
        G_parse_tx_state_did_parse_new();

        // Not done yet => tell host machine to continue sending next RE instruction.
        if (does_instruction_need_to_be_displayed(
                &instruction_parser->instruction,
                &tx_parser->signing.my_derived_public_key.address.public_key)) {
            if (tx_parser->config.parsed_instruction_display_config.display_substate_contents) {
                PRINTF("Newly parsed instruction needs to be displayed to user.\n");
                G_parse_tx_state_ins_needs_approval();

                return ui_display_instruction(&instruction_parser->instruction);
            } else {
                PRINTF(
                    "You have specified to skip displaying contents of instructions => proceeding "
                    "with parsing next.\n");
            }
        } else {
            PRINTF("Finished with instruction which doesn't need to be displayed.\n");
        }

        G_parse_tx_state_ready_to_parse();

        PRINTF(
            "There are more instructions to parse to parse => telling host machine to send more "
            "instructions.\n");
        return io_send_sw(SW_OK);
    }
}

typedef enum {
    PARSE_TX_METADATA_PARSE_BIP32_FAILURE = 1,
    PARSE_TX_METADATA_PARSE_TX_SIZE_FAILURE,
    PARSE_TX_METADATA_PARSE_INSTRUCTION_COUNT_FAILURE,
    PARSE_TX_METADATA_PARSE_OPTIONAL_RRI_HRP_FAILURE,
} parse_tx_metadata_outcome_e;

static bool derive_my_public_key(derived_public_key_t *my_derived_pubkey) {
    // Derive public key according to BIP32 path
    cx_ecfp_private_key_t private_key = {0};
    cx_ecfp_public_key_t public_key = {0};

    // SHOULD _NOT_ return early if `crypto_derive_private_key` or `crypto_init_public_key` fails,
    // because we SHOULD zero out `private_key`.
    bool success = crypto_derive_private_key(&private_key, &my_derived_pubkey->bip32_path) &&
                   crypto_init_public_key(&private_key, &public_key);

    explicit_bzero(&private_key, sizeof(private_key));

    if (!success) {
        return false;
    }

    return crypto_compress_public_key(&public_key, &my_derived_pubkey->address.public_key);
}

static bool parse_tx_parser_config_tx_metadata(buffer_t *buffer,
                                               parse_tx_metadata_outcome_e *outcome,
                                               transaction_metadata_t *metadata,
                                               derived_public_key_t *my_derived_public_key) {
    // PARSE BIP32
    if (!buffer_read_u8(buffer, &my_derived_public_key->bip32_path.path_len) ||
        !buffer_read_bip32_path(buffer, &my_derived_public_key->bip32_path)) {
        *outcome = PARSE_TX_METADATA_PARSE_BIP32_FAILURE;
        return false;
    }

    // PARSE TX size count
    if (!buffer_read_u32(buffer, &metadata->tx_byte_count, BE)) {
        *outcome = PARSE_TX_METADATA_PARSE_TX_SIZE_FAILURE;
        return false;
    }
    metadata->tx_bytes_received_count = 0;

    // PARSE instruction count
    if (!buffer_read_u16(buffer, &metadata->total_number_of_instructions, BE)) {
        *outcome = PARSE_TX_METADATA_PARSE_INSTRUCTION_COUNT_FAILURE;
        return false;
    }
    metadata->number_of_instructions_received = 0;

    // PARSE OPTIONAL HRP of non native token being transferred.
    if (!buffer_read_u8(buffer, &metadata->hrp_non_native_token_len) ||
        metadata->hrp_non_native_token_len > MAX_BECH32_HRP_PART_LEN ||
        !buffer_move_fill_target(buffer,
                                 (uint8_t *) &metadata->hrp_non_native_token,
                                 metadata->hrp_non_native_token_len)) {
        *outcome = PARSE_TX_METADATA_PARSE_OPTIONAL_RRI_HRP_FAILURE;
        return false;
    }

    return true;
}

static bool parse_tx_parser_config(buffer_t *buffer,
                                   parse_tx_metadata_outcome_e *outcome,
                                   transaction_parser_config_t *config,
                                   derived_public_key_t *my_derived_public_key) {
    if (!parse_tx_parser_config_tx_metadata(buffer,
                                            outcome,
                                            &config->transaction_metadata,
                                            my_derived_public_key)) {
        return false;
    }

    config->parsed_instruction_display_config = (const parsed_instruction_display_config_t){
        .display_substate_contents = true,
        .display_tx_summary = true,
    };

    return true;
}

typedef enum {
    SETUP_SIGN_TX_FAILED_TO_PARSE_METADATA = 1,
    SETUP_SIGN_TX_FAILED_TO_DERIVE_MY_PUBLIC_KEY,
} setup_sign_tx_outcome_e;

typedef struct {
    setup_sign_tx_outcome_e outcome_type;
    union {
        parse_tx_metadata_outcome_e metadata_failure;
    };
} setup_sign_tx_outcome_t;

status_word_t sw_from_tx_failure(setup_sign_tx_outcome_t *failure) {
    switch (failure->outcome_type) {
        case SETUP_SIGN_TX_FAILED_TO_PARSE_METADATA:
            switch (failure->metadata_failure) {
                case PARSE_TX_METADATA_PARSE_BIP32_FAILURE:
                    return ERR_CMD_SIGN_TX_PARSE_BIP32_PATH_FAILURE;
                case PARSE_TX_METADATA_PARSE_TX_SIZE_FAILURE:
                    return ERR_CMD_SIGN_TX_PARSE_TX_SIZE_FAILURE;
                case PARSE_TX_METADATA_PARSE_INSTRUCTION_COUNT_FAILURE:
                    return ERR_CMD_SIGN_TX_PARSE_INSTRUCTION_COUNT_FAILURE;
                case PARSE_TX_METADATA_PARSE_OPTIONAL_RRI_HRP_FAILURE:
                    return ERR_CMD_SIGN_TX_PARSE_HRP_FAILED_TO_READ;
            }
        case SETUP_SIGN_TX_FAILED_TO_DERIVE_MY_PUBLIC_KEY:
            return ERR_CMD_SIGN_TX_FAILED_TO_COMPRESS_MY_KEY;
    }
}

static void setup_instruction_parser(instruction_parser_t *ins_parser) {
    // Setup state
    ins_parser->state = STATE_PARSE_INS_READY_TO_PARSE;
}

static bool init_tx_parser(buffer_t *buffer,
                           setup_sign_tx_outcome_t *outcome,
                           transaction_parser_t *tx_parser) {
    // Parse config from buffer
    if (!parse_tx_parser_config(buffer,
                                &outcome->metadata_failure,
                                &tx_parser->config,
                                &tx_parser->signing.my_derived_public_key)) {
        outcome->outcome_type = SETUP_SIGN_TX_FAILED_TO_PARSE_METADATA;
        return false;
    }

    // Need our public key to compare against recipient addresses in transfer/stake to identify
    // spent amount and amounts being change back to ourselves
    if (!derive_my_public_key(&tx_parser->signing.my_derived_public_key)) {
        outcome->outcome_type = SETUP_SIGN_TX_FAILED_TO_DERIVE_MY_PUBLIC_KEY;
        return false;
    }

    // Setup hasher
    cx_sha256_init(&tx_parser->hasher);

    // Setup instruction parser
    setup_instruction_parser(&tx_parser->instruction_parser);

    return true;
}

/**
 * @brief Initiate the sign transaction flow. If successful return \code true, else \code false and
 * \p outcome will contain the failure reason.
 *
 * @param buffer
 * @param outcome Reason for failure.
 * @return true
 * @return false
 */
static bool init_sign_transaction_flow(buffer_t *buffer, setup_sign_tx_outcome_t *outcome) {
    if (!init_tx_parser(buffer, outcome, &G_context.sign_tx_info.transaction_parser)) {
        PRINTF("Failed to initialize transaction parser.\n");
        return false;
    }
    return true;
}

static int handle_initial_setup_apdu(buffer_t *buffer) {
    // Reset all data.
    explicit_bzero(&G_context, sizeof(G_context));

    // Setup parsers for flow
    setup_sign_tx_outcome_t outcome;
    if (!init_sign_transaction_flow(buffer, &outcome)) {
        PRINTF("Failed to initate sign transaction flow.\n");
        status_word_t error_code = sw_from_tx_failure(&outcome);
        return io_send_sw(error_code);
    }

    // Setup state
    G_context.req_type = CONFIRM_TRANSACTION;
    G_context.state = STATE_NONE;

    return io_send_sw(SW_OK);
}

static int handle_single_re_ins_apdu(buffer_t *buffer) {
    return parse_and_process_instruction_from_buffer(buffer,
                                                     &G_context.sign_tx_info.transaction_parser);
}

int handler_sign_tx(buffer_t *cdata, bool is_initial_setup_apdu) {
    if (is_initial_setup_apdu) {
        PRINTF("\n.-~=: SIGN_TX called :=~-.\n\n");
        return handle_initial_setup_apdu(cdata);
    }

    return handle_single_re_ins_apdu(cdata);
}
