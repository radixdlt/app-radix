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

void ui_action_validate_pubkey(bool choice) {
    if (choice) {
        helper_send_response_pubkey();
    } else {
        io_send_sw(SW_DENY);
    }

    ui_menu_main();
}

static void __ui_action_validate_sign_hash_cmd(bool user_approved, bool include_hash_in_response) {
    if (user_approved) {
        G_context.state = STATE_APPROVED;

        if (!crypto_sign_message()) {
            G_context.state = STATE_NONE;
            if (include_hash_in_response) {
                io_send_sw(ERR_CMD_SIGN_TX_ECDSA_SIGN_FAIL);
            } else {
                io_send_sw(ERR_CMD_SIGN_HASH_ECDSA_SIGN_FAIL);
            }

        } else {
            helper_send_response_signature(include_hash_in_response);
        }
    } else {
        G_context.state = STATE_NONE;
        io_send_sw(SW_DENY);
    }

    ui_menu_main();
}
void ui_action_validate_sign_hash(bool choice) {
    return __ui_action_validate_sign_hash_cmd(choice, false);
}

void ui_action_validate_sign_tx(bool choice) {
    return __ui_action_validate_sign_hash_cmd(choice, true);
}

void ui_action_validate_sharedkey(bool choice) {
    if (choice) {
        G_context.state = STATE_APPROVED;
        if (!crypto_ecdh()) {
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