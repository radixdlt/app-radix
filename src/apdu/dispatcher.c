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

#include <stdint.h>
#include <stdbool.h>

#include "dispatcher.h"
#include "../constants.h"
#include "../globals.h"
#include "../state.h"
#include "../io.h"
#include "../sw.h"
#include "../common/buffer.h"
#include "../handler/get_version.h"
#include "../handler/get_app_name.h"
#include "../handler/get_public_key.h"
#include "../handler/sign_tx.h"
#include "../handler/sign_hash.h"
#include "../handler/ecdh.h"

static void fill_buffer(buffer_t *buf, const command_t *cmd) {
    buf->ptr = cmd->data;
    buf->size = cmd->lc;
    buf->offset = 0;
}

int apdu_dispatcher(const command_t *cmd) {
    if (cmd->cla != CLA) {
        return io_send_sw(SW_CLA_NOT_SUPPORTED);
    }

    buffer_t buf = {0};

    // Sign TX variables
    uint8_t P1_FIRST_METADATA_APDU = 77;  // (Ascii code for 'M', as in "Metadata")
    uint8_t P1_SINGLE_RADIX_ENGINE_INSTRUCTION_APDU = 73;
    // (Ascii code for 'I' as in "Instruction")

    uint8_t P2_SINGLE_RADIX_ENGINE_INSTRUCTION_APDU_BITMASK_DISPLAY_SUBSTATE_CONTENT = 0b00000001;
    uint8_t P2_SINGLE_RADIX_ENGINE_INSTRUCTION_APDU_BITMASK_DISPLAY_TX_SUMMARY = 0b00000010;

    bool valid_p1p2 = true;

    switch (cmd->ins) {
        case GET_VERSION:
            if (cmd->p1 != 0 || cmd->p2 != 0) {
                return io_send_sw(SW_WRONG_P1P2);
            }

            return handler_get_version();
        case GET_APP_NAME:
            if (cmd->p1 != 0 || cmd->p2 != 0) {
                return io_send_sw(SW_WRONG_P1P2);
            }

            return handler_get_app_name();
        case GET_PUBLIC_KEY:
            if (cmd->p1 > 1 || cmd->p2 > 0) {
                return io_send_sw(SW_WRONG_P1P2);
            }

            if (!cmd->data) {
                return io_send_sw(SW_WRONG_DATA_LENGTH);
            }

            fill_buffer(&buf, cmd);

            return handler_get_public_key(&buf, (bool) cmd->p1);
        case SIGN_TX:
            if (cmd->p1 == P1_SINGLE_RADIX_ENGINE_INSTRUCTION_APDU) {
                valid_p1p2 = cmd->p2 < 4;
            } else {
                valid_p1p2 = cmd->p1 == P1_FIRST_METADATA_APDU;
            }

            if (!valid_p1p2) {
                return io_send_sw(SW_WRONG_P1P2);
            }

            if (!cmd->data) {
                return io_send_sw(SW_WRONG_DATA_LENGTH);
            }

            fill_buffer(&buf, cmd);

            bool is_first_metadata_apdu = cmd->p1 == P1_FIRST_METADATA_APDU;
            bool display_substate_contents =
                cmd->p1 == P1_SINGLE_RADIX_ENGINE_INSTRUCTION_APDU &&
                (cmd->p2 &
                 P2_SINGLE_RADIX_ENGINE_INSTRUCTION_APDU_BITMASK_DISPLAY_SUBSTATE_CONTENT);
            bool display_tx_summary =
                cmd->p1 == P1_SINGLE_RADIX_ENGINE_INSTRUCTION_APDU &&
                (cmd->p2 & P2_SINGLE_RADIX_ENGINE_INSTRUCTION_APDU_BITMASK_DISPLAY_TX_SUMMARY);

            G_context.tx_info.display_substate_contents = display_substate_contents;
            G_context.tx_info.display_tx_summary = display_tx_summary;

            return handler_sign_tx(&buf, is_first_metadata_apdu);
        case SIGN_HASH:
            if (cmd->p1 > 1 || cmd->p2 > 0) {
                return io_send_sw(SW_WRONG_P1P2);
            }

            if (!cmd->data) {
                return io_send_sw(SW_WRONG_DATA_LENGTH);
            }

            fill_buffer(&buf, cmd);

            return handler_sign_hash(&buf);
        case ECDH:
            if (cmd->p1 > 1 || cmd->p2 > 0) {
                return io_send_sw(SW_WRONG_P1P2);
            }

            if (!cmd->data) {
                return io_send_sw(SW_WRONG_DATA_LENGTH);
            }

            fill_buffer(&buf, cmd);

            return handler_ecdh(&buf, (bool) cmd->p1);

        default:
            return io_send_sw(SW_INS_NOT_SUPPORTED);
    }
}
