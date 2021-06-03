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
#include "../globals.h"
#include "../io.h"
#include "../sw.h"
#include "../account_address.h"
#include "action/validate.h"
#include "../transaction/types.h"
#include "../common/bip32.h"
#include "../common/format.h"
#include "macros.h"  // ASSERT

/// #######################################
/// ####                               ####
/// ####           GLOBAL VARS         ####
/// ####                               ####
/// #######################################
static action_validate_cb g_validate_callback;
static char g_amount[30];
static char g_bip32_path[60];

#define DISPLAYED_HASH_LEN \
    (HASH_LEN * 2 + 1)  // x2 factor for 2chars per bytes in hex and +1 for Null terminator
static char g_hash[DISPLAYED_HASH_LEN];

#define DISPLAYED_ACCOUNT_ADDR_LEN (ACCOUNT_ADDRESS_LEN + 1)  // +1 for Null terminator
static char g_address[DISPLAYED_ACCOUNT_ADDR_LEN];

/// #######################################
/// ####                               ####
/// ####           HELPERS             ####
/// ####                               ####
/// #######################################
static bool set_address(const uint8_t *raw_compressed_pubkey) {
    memset(g_address, 0, sizeof(g_address));

    char address[DISPLAYED_ACCOUNT_ADDR_LEN] = {0};
    size_t address_size_expected = sizeof(address);
    size_t address_size = address_size_expected;

    if (!account_address_from_pubkey(raw_compressed_pubkey, address, &address_size)) {
        return false;
    }

    ASSERT(address_size == address_size_expected, "Incorrect length of account address.");
    snprintf(g_address, sizeof(g_address), "%.*s", address_size, address);

    return true;
}

// Step with approve button
UX_STEP_CB(ux_display_approve_step,
           pb,
           (*g_validate_callback)(true),
           {
               &C_icon_validate_14,
               "Approve",
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
UX_STEP_NOCB(ux_display_confirm_addr_step, pn, {&C_icon_eye, "Confirm Address"});
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
// #1 screen: eye icon + "Confirm Address"
// #2 screen: display BIP32 Path
// #3 screen: display address
// #4 screen: approve button
// #5 screen: reject button
UX_FLOW(ux_display_pubkey_flow,
        &ux_display_confirm_addr_step,
        &ux_display_path_step,
        &ux_display_address_step,
        &ux_display_approve_step,
        &ux_display_reject_step);

int ui_display_address() {
    if (G_context.req_type != CONFIRM_ADDRESS || G_context.state != STATE_NONE) {
        G_context.state = STATE_NONE;
        return io_send_sw(SW_BAD_STATE);
    }

    // Prepare BIP32 path for display
    memset(g_bip32_path, 0, sizeof(g_bip32_path));
    if (!bip32_path_format(G_context.bip32_path,
                           G_context.bip32_path_len,
                           g_bip32_path,
                           sizeof(g_bip32_path))) {
        return io_send_sw(SW_DISPLAY_BIP32_PATH_FAIL);
    }

    // Prepare Address for display
    if (!set_address(G_context.pk_info.raw_compressed_public_key)) {
        return io_send_sw(SW_DISPLAY_ADDRESS_FAIL);
    }

    // Prepare send_response callback if user APPROVEs
    g_validate_callback = &ui_action_validate_pubkey;

    // Initialize (start) the UX flow for SIGN_TX
    ux_flow_init(0, ux_display_pubkey_flow, NULL);

    return 0;
}

/// #######################################
/// ####                               ####
/// ####           SIGN TX             ####
/// ####                               ####
/// #######################################
// Step with icon and text
UX_STEP_NOCB(ux_display_review_step,
             pnn,
             {
                 &C_icon_eye,
                 "Review",
                 "Transaction",
             });
// Step with title/text for amount
UX_STEP_NOCB(ux_display_amount_step,
             bnnn_paging,
             {
                 .title = "Amount",
                 .text = g_amount,
             });

// FLOW to display transaction information:
// #1 screen : eye icon + "Review Transaction"
// #2 screen : display amount
// #3 screen : display destination address
// #4 screen : approve button
// #5 screen : reject button
UX_FLOW(ux_display_transaction_flow,
        &ux_display_review_step,
        &ux_display_address_step,
        &ux_display_amount_step,
        &ux_display_approve_step,
        &ux_display_reject_step);

int ui_display_transaction() {
    if (G_context.req_type != CONFIRM_TRANSACTION || G_context.state != STATE_PARSED) {
        G_context.state = STATE_NONE;
        return io_send_sw(SW_BAD_STATE);
    }

    // Prepare Amount for display
    memset(g_amount, 0, sizeof(g_amount));
    char amount[30] = {0};
    if (!format_fpu64(amount,
                      sizeof(amount),
                      G_context.tx_info.transaction.value,
                      EXPONENT_SMALLEST_UNIT)) {
        return io_send_sw(SW_DISPLAY_AMOUNT_FAIL);
    }
    snprintf(g_amount, sizeof(g_amount), "BOL %.*s", sizeof(amount), amount);
    PRINTF("Amount: %s\n", g_amount);

    // Prepare Address for display
    if (!set_address(G_context.tx_info.transaction.to)) {
        return io_send_sw(SW_DISPLAY_ADDRESS_FAIL);
    }

    // Prepare send_response callback if user APPROVEs
    g_validate_callback = &ui_action_validate_signature;

    // Initialize (start) the UX flow for SIGN_TX
    ux_flow_init(0, ux_display_transaction_flow, NULL);

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

// FLOW to display hash and BIP32 path:
// #1 screen: eye icon + "Sign hash?"
// #2 screen: display BIP32 Path
// #3 screen: display Hash
// #4 screen: approve button
// #5 screen: reject button
UX_FLOW(ux_display_sign_hash_flow,
        &ux_display_confirm_hash_step,
        &ux_display_path_step,
        &ux_display_hash_step,
        &ux_display_approve_step,
        &ux_display_reject_step);

int ui_display_sign_hash() {
    if (G_context.req_type != CONFIRM_HASH) {
        return io_send_sw(SW_BAD_STATE);
    }

    // Prepare BIP32 path for display
    memset(g_bip32_path, 0, sizeof(g_bip32_path));
    if (!bip32_path_format(G_context.bip32_path,
                           G_context.bip32_path_len,
                           g_bip32_path,
                           sizeof(g_bip32_path))) {
        return io_send_sw(SW_DISPLAY_BIP32_PATH_FAIL);
    }

    // Prepare HASH for display
    snprintf(g_hash,
             sizeof(g_hash),
             "%.*h",
             sizeof(G_context.sig_info.m_hash),
             G_context.sig_info.m_hash);

    // Prepare send_response callback if user APPROVEs
    g_validate_callback = &ui_action_validate_signature;

    // Initialize (start) the UX flow for SIGN_HASH
    ux_flow_init(0, ux_display_sign_hash_flow, NULL);

    return 0;
}