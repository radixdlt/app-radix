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
#include "../types/status_word.h"
#include "../types/public_key.h"
#include "../instruction/instruction.h"

#include "../common/bech32_encode.h"
#include "../common/read.h"    // read_u16_be, read_u32_be
#include "../common/format.h"  // print_uint256
#include "../transaction/transaction_parser.h"

#include "../helper/send_response.h"

typedef enum {
    SETUP_SIGN_TX_FAILED_TO_PARSE_TX_CONFIG_FROM_BUFFER,
    SETUP_SIGN_TX_FAILED_TO_PARSE_INIT_PARSER_WITH_CONFIG,
} setup_sign_tx_outcome_e;

typedef struct {
    setup_sign_tx_outcome_e outcome_type;
    union {
        parse_tx_config_outcome_e parse_config_failure;
        init_tx_parser_outcome_t init_tx_parser_failure;
    };
} setup_sign_tx_outcome_t;

status_word_t status_word_for_setup_sign_tx_failure(setup_sign_tx_outcome_t *failure) {
    switch (failure->outcome_type) {
        case SETUP_SIGN_TX_FAILED_TO_PARSE_TX_CONFIG_FROM_BUFFER:
            switch (failure->parse_config_failure) {
                case PARSE_TX_CONFIG_BIP32_FAILURE:
                    return ERR_CMD_SIGN_TX_PARSE_BIP32_PATH_FAILURE;
                case PARSE_TX_CONFIG_TX_SIZE_FAILURE:
                    return ERR_CMD_SIGN_TX_PARSE_TX_SIZE_FAILURE;
                case PARSE_TX_CONFIG_INSTRUCTION_COUNT_FAILURE:
                    return ERR_CMD_SIGN_TX_PARSE_INSTRUCTION_COUNT_FAILURE;
                case PARSE_TX_CONFIG_OPTIONAL_RRI_HRP_FAILURE:
                    return ERR_CMD_SIGN_TX_PARSE_HRP_FAILED_TO_READ;
            }
        case SETUP_SIGN_TX_FAILED_TO_PARSE_INIT_PARSER_WITH_CONFIG:
            return ERR_CMD_SIGN_TX_INVALID_CONFIG;
    }
}

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

static cx_sha256_t hasher_ledger;

static void init_impl_hasher() {
    // Setup Ledger SDK hasher
    cx_sha256_init(&hasher_ledger);
}

static bool update_hash_ledger_sdk(buffer_t *buffer, bool finalize, uint8_t *out) {
    return sha256_hash_ledger_sdk(&hasher_ledger, buffer, finalize, out);
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
static bool init_sign_transaction_flow(buffer_t *buffer,
                                       setup_sign_tx_outcome_t *outcome,
                                       transaction_parser_t *tx_parser) {
    init_transaction_parser_config_t parsed_config;
    if (!parse_tx_parser_config(buffer, &outcome->parse_config_failure, &parsed_config)) {
        PRINTF("Failed to parse transaction parser config from buffer.\n");
        outcome->outcome_type = SETUP_SIGN_TX_FAILED_TO_PARSE_TX_CONFIG_FROM_BUFFER;
        return false;
    }

    derive_my_pubkey_key_fn derive_my_pubkey = &derive_my_public_key;

    if (!init_tx_parser_with_config(tx_parser,
                                    derive_my_pubkey,
                                    &update_hash_ledger_sdk,
                                    &init_impl_hasher,
                                    &parsed_config,
                                    &outcome->init_tx_parser_failure)) {
        PRINTF("Failed to initialize transaction parser.\n");
        outcome->outcome_type = SETUP_SIGN_TX_FAILED_TO_PARSE_INIT_PARSER_WITH_CONFIG;
        return false;
    }
    return true;
}

static int handle_initial_setup_apdu(buffer_t *buffer, transaction_parser_t *tx_parser) {
    // Reset all data.
    explicit_bzero(&G_context, sizeof(G_context));

    // Setup parsers for flow
    setup_sign_tx_outcome_t outcome;
    if (!init_sign_transaction_flow(buffer, &outcome, tx_parser)) {
        PRINTF("Failed to initate sign transaction flow.\n");
        status_word_t error_code = status_word_for_setup_sign_tx_failure(&outcome);
        return io_send_sw(error_code);
    }

    // Setup state
    G_context.req_type = CONFIRM_TRANSACTION;
    G_context.state = STATE_NONE;

    return io_send_sw(SW_OK);
}

static int ux_finished_parsing_tx(transaction_parser_t *tx_parser) {
    G_parse_tx_state_finished_parsing_all();
    G_context.state = STATE_PARSED;
    if (!tx_parser->instruction_display_config.display_tx_summary) {
        if (!crypto_sign_message(&tx_parser->signing)) {
            return io_send_sw(ERR_CMD_SIGN_TX_ECDSA_SIGN_FAIL);
        } else {
            bool include_hash_in_response = true;
            return helper_send_response_signature(include_hash_in_response, &tx_parser->signing);
        }
    }

    return ui_display_tx_summary(&tx_parser->transaction,
                                 &tx_parser->signing.my_derived_public_key.bip32_path,
                                 tx_parser->signing.hasher.hash

    );
}

static int ux_display_new_instruction_if_needed(transaction_parser_t *tx_parser) {
    G_parse_tx_state_did_parse_new();
    bool display_ins = does_instruction_need_to_be_displayed(
                           &tx_parser->instruction_parser.instruction,
                           &tx_parser->signing.my_derived_public_key.address.public_key) &&
                       tx_parser->instruction_display_config.display_substate_contents;

    if (display_ins) {
        G_parse_tx_state_ins_needs_approval();
        return ui_display_instruction(&tx_parser->instruction_parser.instruction);
    } else {
        G_parse_tx_state_ready_to_parse();
        return io_send_sw(SW_OK);
    }
}

static int handle_single_re_ins_apdu(buffer_t *buffer, transaction_parser_t *tx_parser) {
    parse_and_process_instruction_outcome_t outcome;

    if (!parse_and_process_instruction_from_buffer(buffer, tx_parser, &outcome)) {
        // Failed to parse and process
        status_word_t sw_error = status_word_for_parse_and_process_ins_failure(&outcome);
        return io_send_sw(sw_error);
    }
    switch (outcome.outcome_type) {
        case PARSE_PROCESS_INS_SUCCESS_FINISHED_PARSING_WHOLE_TRANSACTION:
            return ux_finished_parsing_tx(tx_parser);
        case PARSE_PROCESS_INS_SUCCESS_FINISHED_PARSING_INS:
            return ux_display_new_instruction_if_needed(tx_parser);
        default:
            PRINTF("\n\nFailed to parse and process instruction from buffer.\n\n");
            // print_parse_process_instruction_outcome(&outcome);
            break;
    }

    return io_send_sw(ERR_BAD_STATE);
}

int handler_sign_tx(buffer_t *cdata, bool is_initial_setup_apdu) {
    transaction_parser_t *tx_parser = &G_context.sign_tx_info.transaction_parser;
    if (is_initial_setup_apdu) {
        PRINTF("\n.-~=: SIGN_TX called :=~-.\n\n");
        return handle_initial_setup_apdu(cdata, tx_parser);
    }

    return handle_single_re_ins_apdu(cdata, tx_parser);
}
