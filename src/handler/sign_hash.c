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
#include <string.h>

#include "sign_hash.h"
#include "../constants.h"
#include "../globals.h"
#include "../ui/display.h"

int handler_sign_hash(buffer_t *cdata) {
    PRINTF("\n.-~=: SIGN_HASH called :=~-.\n\n");
    explicit_bzero(&G_context, sizeof(G_context));
    G_context.req_type = CONFIRM_HASH;
    G_context.state = STATE_NONE;

    if (!buffer_read_u8(
            cdata,
            &G_context.sign_hash_info.signing.my_derived_public_key.bip32_path.path_len) ||
        !buffer_read_bip32_path(
            cdata,
            &G_context.sign_hash_info.signing.my_derived_public_key.bip32_path)) {
        return io_send_sw(SW_WRONG_DATA_LENGTH);
    }

    uint8_t hash_len;
    if (!buffer_read_u8(cdata, &hash_len) || hash_len != HASH_LEN) {
        return io_send_sw(ERR_CMD_SIGN_HASH_PARSE_HASH_FAILURE_BAD_LENGTH);
    }

    if (!buffer_move_fill_target(cdata, G_context.sign_hash_info.signing.hasher.hash, hash_len)) {
        return io_send_sw(ERR_CMD_SIGN_HASH_PARSE_HASH_FAILURE_TOO_SHORT);
    }

    PRINTF("Hash: %.*H\n",
           sizeof(G_context.sign_hash_info.signing.hasher.hash),
           G_context.sign_hash_info.signing.hasher.hash);

    return ui_display_sign_hash(&G_context.sign_hash_info.signing.my_derived_public_key.bip32_path,
                                G_context.sign_hash_info.signing.hasher.hash,
                                sizeof(G_context.sign_hash_info.signing.hasher.hash));
}
