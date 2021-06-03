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

#include "diffie_hellman.h"
#include "../common/buffer.h"

#include "os.h"
#include "sw.h"     // SW_WRONG_DATA_LENGTH
#include "../io.h"  // io_send_sw

#include "../globals.h"               // G_context
#include "../crypto.h"                // crypto_init_public_key_from_raw_uncompressed
#include "../ui/display.h"            // ui_display_ecdh
#include "../helper/send_response.h"  // helper_send_response_sharedkey

int handler_diffie_hellman(buffer_t *cdata, bool display) {
    PRINTF("DIFFIE_HELLMAN key exchange (ECDH) called.");
    explicit_bzero(&G_context, sizeof(G_context));
    G_context.req_type = CONFIRM_ECDH;
    G_context.state = STATE_NONE;

    if (!buffer_read_u8(cdata, &G_context.bip32_path_len) ||
        !buffer_read_bip32_path(cdata, G_context.bip32_path, (size_t) G_context.bip32_path_len)) {
        return io_send_sw(SW_WRONG_DATA_LENGTH);
    }

    uint8_t pubkey_other_party_len;
    if (!buffer_read_u8(cdata, &pubkey_other_party_len) ||
        pubkey_other_party_len != PUBLIC_KEY_POINT_LEN) {
        return io_send_sw(SW_WRONG_DATA_LENGTH);
    }

    uint8_t tmp_raw_key[PUBLIC_KEY_POINT_LEN];

    if (!buffer_move(cdata, tmp_raw_key, pubkey_other_party_len)) {
        return io_send_sw(SW_WRONG_DATA_LENGTH);
    }

    if (!crypto_init_public_key_from_raw_uncompressed(
            tmp_raw_key,
            &G_context.ecdh_info.other_party_public_key)) {
        return io_send_sw(SW_ECDH_FAILED_TO_PARSE_PUBKEY);
    }

    PRINTF("Public key of other party: %.*H\n",
           G_context.ecdh_info.other_party_public_key.W_len,
           G_context.ecdh_info.other_party_public_key.W);

    if (display) {
        return ui_display_ecdh();
    }

    return helper_send_response_sharedkey();
}