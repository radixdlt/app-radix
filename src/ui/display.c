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

#pragma GCC diagnostic ignored "-Wformat"  // snprintf

#include <stdbool.h>  // bool
#include <string.h>   // memset

#include "os.h"
#include "ux.h"
#include "glyphs.h"

#include "display.h"
#include "constants.h"
#include "../crypto.h"
#include "../globals.h"
#include "../io.h"
#include "../sw.h"
#include "action/validate.h"
#include "../types/re_address.h"
#include "../types/bip32_path.h"
#include "../common/format.h"
#include "../macros.h"  // ASSERT

/// #######################################
/// ####                               ####
/// ####           GLOBAL VARS         ####
/// ####                               ####
/// #######################################
static action_validate_cb g_validate_callback;

static char g_bip32_path[60];

#define DISPLAYED_AMOUNT_LEN              \
    (UINT256_DEC_STRING_MAX_LENGTH + 10 + \
     1)  // +10 for length of "E-18 XRD: ", +1 for Null terminator
static char g_amount[DISPLAYED_AMOUNT_LEN];
static char g_tx_fee[DISPLAYED_AMOUNT_LEN];

#define DISPLAYED_HASH_LEN \
    (HASH_LEN * 2 + 1)  // x2 factor for 2chars per bytes in hex and +1 for Null terminator
static char g_hash[DISPLAYED_HASH_LEN];

#define DISPLAYED_ACCOUNT_ADDR_LEN (ACCOUNT_ADDRESS_LEN + 1)  // +1 for Null terminator
static char g_address[DISPLAYED_ACCOUNT_ADDR_LEN];

#define DISPLAYED_RRI_LEN DISPLAYED_ACCOUNT_ADDR_LEN
static char g_rri[DISPLAYED_RRI_LEN];

/// #######################################
/// ####                               ####
/// ####           HELPERS             ####
/// ####                               ####
/// #######################################
static void prepare_ui_for_new_flow(void) {
    explicit_bzero(g_amount, sizeof(g_amount));
    explicit_bzero(g_address, sizeof(g_amount));
    explicit_bzero(g_rri, sizeof(g_rri));
    explicit_bzero(g_hash, sizeof(g_hash));
    explicit_bzero(g_tx_fee, sizeof(g_tx_fee));
    explicit_bzero(g_bip32_path, sizeof(g_bip32_path));
}

static bool format_account_address_for_display(re_address_t *re_address) {
    explicit_bzero(g_address, sizeof(g_address));
    return format_account_address_from_re_address(re_address, g_address, sizeof(g_address));
}

static bool format_validator_address_for_display(re_address_t *re_address) {
    explicit_bzero(g_address, sizeof(g_address));
    return format_validator_address_from_re_address(re_address, g_address, sizeof(g_address));
}

static bool format_native_token_for_display(re_address_t *re_address) {
    explicit_bzero(g_rri, sizeof(g_rri));
    return format_native_token_from_re_address(re_address, g_rri, sizeof(g_rri));
}

static bool format_other_token_for_display(re_address_t *re_address,
                                           char *rri_hrp,
                                           const size_t rri_hrp_len) {
    explicit_bzero(g_rri, sizeof(g_rri));
    return format_other_token_from_re_address(re_address,
                                              rri_hrp,
                                              rri_hrp_len,
                                              g_rri,
                                              sizeof(g_rri));
}

static bool format_bip32_path(bip32_path_t *bip32) {
    explicit_bzero(g_bip32_path, sizeof(g_bip32_path));
    return bip32_path_format(bip32, g_bip32_path, sizeof(g_bip32_path));
}

// Step with approve button
UX_STEP_CB(ux_display_approve_step,
           pb,
           (*g_validate_callback)(true),
           {
               &C_icon_validate_14,
               "Approve",
           });

// Step with approve button (but with text "Sign tx?")
UX_STEP_CB(ux_display_approve_sign_tx_step,
           pb,
           (*g_validate_callback)(true),
           {
               &C_icon_validate_14,
               "Sign tx?",
           });
// Step with reject button
UX_STEP_CB(ux_display_reject_step,
           pb,
           (*g_validate_callback)(false),
           {
               &C_icon_crossmark,
               "Reject",
           });

/// #######################################
/// ####                               ####
/// ####           GET_PUB_KEY         ####
/// ####                               ####
/// #######################################
// Step with icon and text
UX_STEP_NOCB(ux_display_verify_addr_step, pn, {&C_icon_eye, "Verify address"});

// Step with title/text for BIP32 path
UX_STEP_NOCB(ux_display_path_step,
             bnnn_paging,
             {
                 .title = "Path",
                 .text = g_bip32_path,
             });
// Step with title/text for address
UX_STEP_NOCB(ux_display_address_step,
             bnnn_paging,
             {
                 .title = "Address",
                 .text = g_address,
             });

// FLOW to display address and BIP32 path:
// #1 screen: eye icon + "Verify Address"
// #2 screen: display BIP32 Path
// #3 screen: display address
// #4 screen: approve button
// #5 screen: reject button
UX_FLOW(ux_display_pubkey_flow,
        &ux_display_verify_addr_step,
        &ux_display_path_step,
        &ux_display_address_step,
        &ux_display_approve_step,
        &ux_display_reject_step);

// FLOW to display only account address
// #1 screen: eye icon + "Verify Address"
// #2 screen: display address
UX_FLOW(ux_display_verify_address_flow,
        &ux_display_verify_addr_step,
        &ux_display_address_step,
        &ux_display_approve_step);

int ui_display_address_from_get_pubkey_cmd(derived_public_key_t *my_derived_public_key,
                                           bool address_verification_only) {
    prepare_ui_for_new_flow();

    if (G_context.req_type != CONFIRM_ADDRESS || G_context.state != STATE_NONE) {
        G_context.state = STATE_NONE;
        return io_send_sw(ERR_BAD_STATE);
    }

    // Prepare BIP32 path for display (skipped if `address_verification_only`)
    if (!format_bip32_path(&my_derived_public_key->bip32_path)) {
        return io_send_sw(ERR_DISPLAY_BIP32_PATH_FAIL);
    }

    // Prepare Address for display
    if (!format_account_address_for_display(&my_derived_public_key->address)) {
        return io_send_sw(ERR_DISPLAY_ADDRESS_FAIL);
    }

    // Prepare send_response callback if user APPROVEs
    g_validate_callback = &ui_action_validate_pubkey;

    // Initialize (start) the UX flow for display public key/address info
    if (address_verification_only) {
        // This skips showing BIP32 path
        ux_flow_init(0, ux_display_verify_address_flow, NULL);
    } else {
        ux_flow_init(0, ux_display_pubkey_flow, NULL);
    }

    return 0;
}

/// #######################################
/// ####                               ####
/// ####           SIGN HASH           ####
/// ####                               ####
/// #######################################
// Step with icon and text
UX_STEP_NOCB(ux_display_confirm_hash_step, pn, {&C_icon_eye, "Sign hash?"});

// Step with title/text for hash
UX_STEP_NOCB(ux_display_hash_step,
             bnnn_paging,
             {
                 .title = "Hash",
                 .text = g_hash,
             });

UX_STEP_NOCB(ux_display_sign_with_key_at_path_step,
             bnnn_paging,
             {
                 .title = "Signing key path",
                 .text = g_bip32_path,
             });

// FLOW to display hash and BIP32 path:
// #1 screen: eye icon + "Sign hash?"
// #2 screen: display BIP32 Path
// #3 screen: display Hash
// #4 screen: approve button
// #5 screen: reject button
UX_FLOW(ux_display_sign_hash_flow,
        &ux_display_confirm_hash_step,
        &ux_display_sign_with_key_at_path_step,
        &ux_display_hash_step,
        &ux_display_approve_step,
        &ux_display_reject_step);

int ui_display_sign_hash(bip32_path_t *bip32_path, uint8_t *hash, size_t hash_len) {
    prepare_ui_for_new_flow();

    if (G_context.req_type != CONFIRM_HASH) {
        return io_send_sw(ERR_BAD_STATE);
    }

    // Prepare BIP32 path for display
    if (!format_bip32_path(bip32_path)) {
        return io_send_sw(ERR_DISPLAY_BIP32_PATH_FAIL);
    }

    // Prepare HASH for display
    snprintf(g_hash, sizeof(g_hash), "%.*h", hash_len, hash);

    // Prepare send_response callback if user APPROVEs
    g_validate_callback = &ui_action_validate_sign_hash;

    // Initialize (start) the UX flow for SIGN_HASH
    ux_flow_init(0, ux_display_sign_hash_flow, NULL);

    return 0;
}

/// #######################################
/// ####                               ####
/// ####      ECDH Key Exchange        ####
/// ####                               ####
/// #######################################
// Step with icon and text
UX_STEP_NOCB(ux_display_confirm_other_pubkey_step, pn, {&C_icon_eye, "ECDH with?"});

// Step with title/text for public key of other party
UX_STEP_NOCB(ux_display_other_party_address_step,
             bnnn_paging,
             {
                 .title = "Pubkey other",
                 .text = g_address,
             });

// Step with title/text for BIP32 path
UX_STEP_NOCB(ux_display_path_key_step,
             bnnn_paging,
             {
                 .title = "Your key at",
                 .text = g_bip32_path,
             });

// FLOW to display other party pubkey and BIP32 path:
// #1 screen: eye icon + "ECDH with?"
// #3 screen: display address of other party
// #2 screen: display BIP32 Path
// #4 screen: approve button
// #5 screen: reject button
UX_FLOW(ux_display_ecdh_flow,
        &ux_display_confirm_other_pubkey_step,
        &ux_display_other_party_address_step,
        &ux_display_path_key_step,
        &ux_display_approve_step,
        &ux_display_reject_step);

int ui_display_ecdh(derived_public_key_t *my_derived_public_key,
                    re_address_t *other_party_address) {
    prepare_ui_for_new_flow();

    if (G_context.req_type != CONFIRM_ECDH) {
        return io_send_sw(ERR_BAD_STATE);
    }

    // Prepare BIP32 path for display
    if (!format_bip32_path(&my_derived_public_key->bip32_path)) {
        return io_send_sw(ERR_DISPLAY_BIP32_PATH_FAIL);
    }

    // Prepare to display other party address
    if (!format_account_address_for_display(other_party_address)) {
        return io_send_sw(ERR_DISPLAY_ADDRESS_FAIL);
    }

    // Prepare send_response callback if user APPROVEs
    g_validate_callback = &ui_action_validate_sharedkey;

    // Initialize (start) the UX flow for ECDH key exchange
    ux_flow_init(0, ux_display_ecdh_flow, NULL);

    return 0;
}

/// #######################################
/// ####                               ####
/// ####           SIGN TX             ####
/// ####                               ####
/// #######################################

/// ******************
/// **    SUMMARY   **
/// ******************
// Step with icon and text
UX_STEP_NOCB(ux_display_review_tx_summary_step,
             pnn,
             {
                 &C_icon_eye,
                 "Review",
                 "Transaction",
             });
// Step with title/text for amount
UX_STEP_NOCB(ux_display_total_xrd_incl_fee_amount_step,
             bnnn_paging,
             {
                 .title = "Total XRD",
                 .text = g_amount,
             });

// Step with title/text for amount
UX_STEP_NOCB(ux_display_tx_fee_amount_step,
             bnnn_paging,
             {
                 .title = "Fee in XRD",
                 .text = g_tx_fee,
             });

// Step with title/text for amount
UX_STEP_NOCB(ux_display_tx_hash_step,
             bnnn_paging,
             {
                 .title = "Hash of TX",
                 .text = g_hash,
             });

// FLOW to display summary of transaction information:
UX_FLOW(
    ux_display_tx_summary_flow,
    &ux_display_review_tx_summary_step,          // #1 screen: eye icon + "Review Transaction"
    &ux_display_tx_fee_amount_step,              // #2 screen: display tx fee amount
    &ux_display_total_xrd_incl_fee_amount_step,  // #3 screen: display total XRD amount
    &ux_display_tx_hash_step,                    // #4 screen: display tx hash
    &ux_display_sign_with_key_at_path_step,  // # 5 screen: display Bip32 path for key to sign with
    &ux_display_approve_sign_tx_step,        // #6 screen: approve button
    &ux_display_reject_step);                // #7 screen: reject button

int ui_display_tx_summary(transaction_t *transaction,
                          bip32_path_t *bip32_path,
                          uint8_t hash[static HASH_LEN]) {
    prepare_ui_for_new_flow();

    if (G_context.req_type != CONFIRM_TRANSACTION || G_context.state != STATE_PARSED) {
        G_context.state = STATE_NONE;
        return io_send_sw(ERR_BAD_STATE);
    }

    // Prepare BIP32 path for display
    if (!format_bip32_path(bip32_path)) {
        return io_send_sw(ERR_DISPLAY_BIP32_PATH_FAIL);
    }

    char amount[DISPLAYED_AMOUNT_LEN] = {0};

    if (!to_string_uint256(&transaction->tx_fee, amount, sizeof(amount))) {
        return io_send_sw(ERR_DISPLAY_AMOUNT_FAIL);
    }
    snprintf(g_tx_fee, sizeof(g_tx_fee), "E-18 XRD: %.*s", sizeof(amount), amount);
    PRINTF("Tx fee: %s\n", g_tx_fee);

    explicit_bzero(amount, sizeof(amount));
    if (!to_string_uint256(&transaction->total_xrd_amount_incl_fee, amount, sizeof(amount))) {
        return io_send_sw(ERR_DISPLAY_AMOUNT_FAIL);
    }

    snprintf(g_amount, sizeof(g_amount), "E-18 XRD: %.*s", sizeof(amount), amount);
    PRINTF("Amount: %s\n", g_amount);

    // Prepare HASH for display
    snprintf(g_hash, sizeof(g_hash), "%.*h", HASH_LEN, hash);

    g_validate_callback = &ui_action_validate_sign_tx;

    ux_flow_init(0, ux_display_tx_summary_flow, NULL);

    return 0;
}

/// $$$$$$$$$$$$$$$$$$$$$$
/// $$  Token Transfer  $$
/// $$$$$$$$$$$$$$$$$$$$$$
// Step with icon and text
UX_STEP_NOCB(ux_display_review_ins_up_tokens_step,
             pnn,
             {
                 &C_icon_eye,
                 "Review",
                 "Transfer",
             });
// Step with title/text for amount
UX_STEP_NOCB(ux_display_recipient_address_step,
             bnnn_paging,
             {
                 .title = "To",
                 .text = g_address,
             });

// Step with title/text for amount
UX_STEP_NOCB(ux_display_token_rri_step,
             bnnn_paging,
             {
                 .title = "Token (rri)",
                 .text = g_rri,
             });

// Step with title/text for amount
UX_STEP_NOCB(ux_display_amount_step,
             bnnn_paging,
             {
                 .title = "Amount",
                 .text = g_amount,
             });

// FLOW to display summary of UP(TOKENS) instruction information:
UX_FLOW(ux_display_instruction_tokens_flow,
        &ux_display_review_ins_up_tokens_step,  // #1 screen: eye icon + "Review Transfer"
        &ux_display_recipient_address_step,     // #2 screen: display recipient address
        &ux_display_token_rri_step,             // #3 screen: display token (rri)
        &ux_display_amount_step,                // #4 screen: display amount
        &ux_display_approve_step,               // #5 screen: approve button
        &ux_display_reject_step);               // #6 screen: reject button

static void ui_display_tokens(tokens_t *tokens) {
    PRINTF("START: ui_display_tokens.\n");

    prepare_ui_for_new_flow();

    // Prepare 'recipient' address for display
    if (!format_account_address_for_display(&tokens->owner)) {
        io_send_sw(ERR_DISPLAY_ADDRESS_FAIL);
        return;
    }

    // Prepare tokens RRI
    transaction_metadata_t *tx_metadata =
        &G_context.sign_tx_info.transaction_parser.transaction_metadata;
    if (tokens->rri.address_type == RE_ADDRESS_HASHED_KEY_NONCE) {
        // Would be nice to avoid this global state access...
        if (tx_metadata->hrp_non_native_token_len == 0) {
            io_send_sw(ERR_DISPLAY_RRI_FAIL);
            return;
        }

        // Would be nice to avoid this global state access...
        if (!format_other_token_for_display(&tokens->rri,
                                            tx_metadata->hrp_non_native_token,
                                            tx_metadata->hrp_non_native_token_len)) {
            io_send_sw(ERR_DISPLAY_RRI_FAIL);
            return;
        }
    } else {
        if (!format_native_token_for_display(&tokens->rri)) {
            io_send_sw(ERR_DISPLAY_RRI_FAIL);
            return;
        }
    }

    // Prepare 'amount' staked for display
    char amount[DISPLAYED_AMOUNT_LEN] = {0};
    if (!to_string_uint256(&tokens->amount, amount, sizeof(amount))) {
        io_send_sw(ERR_DISPLAY_AMOUNT_FAIL);
        return;
    }
    snprintf(g_amount, sizeof(g_amount), "E-18: %.*s", sizeof(amount), amount);
    PRINTF("Amount: %s\n", g_amount);

    ux_flow_init(0, ux_display_instruction_tokens_flow, NULL);
}

/// $$$$$$$$$$$$$$$$$$$$$$
/// $$  Stake Tokens    $$
/// $$$$$$$$$$$$$$$$$$$$$$
UX_STEP_NOCB(ux_display_review_ins_up_prepared_stake_step,
             pnn,
             {
                 &C_icon_eye,
                 "Review",
                 "Stake",
             });
// Step with title/text for amount
UX_STEP_NOCB(ux_display_to_validator_address_step,
             bnnn_paging,
             {
                 .title = "To validator",
                 .text = g_address,
             });

// FLOW to display summary of UP(PREPARED_STAKE) instruction information:
UX_FLOW(ux_display_instruction_prepared_stake_flow,
        &ux_display_review_ins_up_prepared_stake_step,  // #1 screen: eye icon + "Review Stake"
        &ux_display_to_validator_address_step,          // #2 screen: display validator address
        &ux_display_amount_step,                        // #3 screen: display amount
        &ux_display_approve_step,                       // #4 screen: approve button
        &ux_display_reject_step);                       // #5 screen: reject button

static void ui_display_stake(prepared_stake_t *prepared_stake) {
    PRINTF("START: ui_display_stake.\n");
    prepare_ui_for_new_flow();
    // Prepare 'to validator' address for display
    if (!format_validator_address_for_display(&prepared_stake->delegate)) {
        io_send_sw(ERR_DISPLAY_ADDRESS_FAIL);
        return;
    }

    // Prepare 'amount' staked for display
    char amount[DISPLAYED_AMOUNT_LEN] = {0};
    if (!to_string_uint256(&prepared_stake->amount, amount, sizeof(amount))) {
        io_send_sw(ERR_DISPLAY_AMOUNT_FAIL);
        return;
    }
    snprintf(g_amount, sizeof(g_amount), "XRD %.*s", sizeof(amount), amount);
    PRINTF("Amount: %s\n", g_amount);

    ux_flow_init(0, ux_display_instruction_prepared_stake_flow, NULL);
    return;
}

/// $$$$$$$$$$$$$$$$$$$$$$
/// $$  Untake Tokens   $$
/// $$$$$$$$$$$$$$$$$$$$$$
UX_STEP_NOCB(ux_display_review_ins_up_prepared_unstake_step,
             pnn,
             {
                 &C_icon_eye,
                 "Review",
                 "Unstake",
             });
// Step with title/text for amount
UX_STEP_NOCB(ux_display_from_validator_address_step,
             bnnn_paging,
             {
                 .title = "From validator",
                 .text = g_address,
             });

// FLOW to display summary of UP(PREPARED_UNSTAKE) instruction information:
UX_FLOW(ux_display_instruction_prepared_unstake_flow,
        &ux_display_review_ins_up_prepared_unstake_step,  // #1 screen: eye icon + "Review Unstake"
        &ux_display_from_validator_address_step,          // #2 screen: display validator address
        &ux_display_amount_step,                          // #3 screen: display amount
        &ux_display_approve_step,                         // #4 screen: approve button
        &ux_display_reject_step);                         // #5 screen: reject button

static void ui_display_unstake(prepared_unstake_t *prepared_unstake) {
    PRINTF("START: ui_display_unstake.\n");
    prepare_ui_for_new_flow();

    // Prepare 'from validator' address for display
    if (!format_validator_address_for_display(&prepared_unstake->delegate)) {
        io_send_sw(ERR_DISPLAY_ADDRESS_FAIL);
        return;
    }

    // Prepare 'amount' staked for display
    char amount[DISPLAYED_AMOUNT_LEN] = {0};
    if (!to_string_uint256(&prepared_unstake->amount, amount, sizeof(amount))) {
        io_send_sw(ERR_DISPLAY_AMOUNT_FAIL);
        return;
    }
    snprintf(g_amount, sizeof(g_amount), "XRD %.*s", sizeof(amount), amount);
    PRINTF("Amount: %s\n", g_amount);

    ux_flow_init(0, ux_display_instruction_prepared_unstake_flow, NULL);
    return;
}

int ui_display_instruction(re_instruction_t *instruction) {
    PRINTF("START: ui_display_instruction.\n");
    prepare_ui_for_new_flow();

    if (G_context.req_type != CONFIRM_TRANSACTION || G_context.state != STATE_NONE ||
        instruction->ins_type != INS_UP) {
        G_context.state = STATE_NONE;
        return io_send_sw(ERR_BAD_STATE);
    }

    g_validate_callback = &ui_action_validate_instruction;

    switch (instruction->ins_up.substate.type) {
        case SUBSTATE_TYPE_TOKENS:
            ui_display_tokens(&instruction->ins_up.substate.tokens);
            break;
        case SUBSTATE_TYPE_PREPARED_STAKE:
            ui_display_stake(&instruction->ins_up.substate.prepared_stake);
            break;
        case SUBSTATE_TYPE_PREPARED_UNSTAKE:
            ui_display_unstake(&instruction->ins_up.substate.prepared_unstake);
            break;
        default:
            PRINTF("Trying to display a substate type that should not be displayed\n");
            // print_re_substate_type(instruction->ins_up.substate.type);
            return io_send_sw(ERR_BAD_STATE);
    }

    return 0;
}
