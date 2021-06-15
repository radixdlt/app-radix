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

#include <stdbool.h>  // bool

#include "validate.h"
#include "../menu.h"
#include "../../sw.h"
#include "../../io.h"
#include "../../crypto.h"
#include "../../globals.h"
#include "../../helper/send_response.h"

void ui_action_validate_pubkey(user_accepted_t user_accepted) {
    if (user_accepted) {
        helper_send_response_pubkey();
    } else {
        io_send_sw(SW_DENY);
    }

    ui_menu_main();
}

static void __ui_action_validate_sign_hash_cmd(user_accepted_t user_accepted,
                                               bool include_hash_in_response,
                                               signing_t *signing

) {
    if (user_accepted) {
        G_context.state = STATE_APPROVED;

        if (!crypto_sign_message(signing)) {
            G_context.state = STATE_NONE;
            if (include_hash_in_response) {
                io_send_sw(ERR_CMD_SIGN_TX_ECDSA_SIGN_FAIL);
            } else {
                io_send_sw(ERR_CMD_SIGN_HASH_ECDSA_SIGN_FAIL);
            }

        } else {
            helper_send_response_signature(include_hash_in_response, signing);
        }
    } else {
        G_context.state = STATE_NONE;
        io_send_sw(SW_DENY);
    }

    ui_menu_main();
}

void ui_action_validate_instruction(user_accepted_t user_accepted) {
    if (!user_accepted) {
        G_context.state = STATE_NONE;
        io_send_sw(SW_DENY);
        ui_menu_main();
        return;
    }

    G_parse_tx_state_did_approve_ins();
    G_parse_tx_state_ready_to_parse();

    // Not done yet => tell host machine to continue sending next RE instruction.
    io_send_sw(SW_OK);
    return;
}

void ui_action_validate_sign_hash(user_accepted_t user_accepted) {
    return __ui_action_validate_sign_hash_cmd(user_accepted,
                                              false,
                                              &G_context.sign_hash_info.signing);
}

void ui_action_validate_sign_tx(user_accepted_t user_accepted) {
    // TODO refactor to avoid GLOBAL state/variable access. Hmm, maybe we can
    return __ui_action_validate_sign_hash_cmd(user_accepted,
                                              true,
                                              &G_context.sign_tx_info.transaction_parser.signing);
}

void ui_action_validate_sharedkey(user_accepted_t user_accepted) {
    if (user_accepted) {
        G_context.state = STATE_APPROVED;
        if (!crypto_ecdh(&G_context.ecdh_info.my_derived_public_key.bip32_path,
                         &G_context.ecdh_info.other_party_public_key,
                         G_context.ecdh_info.shared_pubkey_point)) {
            G_context.state = STATE_NONE;
            io_send_sw(ERR_CMD_ECDH_COMPUTE_SHARED_KEY_FAILURE);
        } else {
            helper_send_response_sharedkey();
        }
    } else {
        G_context.state = STATE_NONE;
        io_send_sw(SW_DENY);
    }

    ui_menu_main();
}