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
#include <string.h>   // memset, explicit_bzero

#include "os.h"
#include "cx.h"

#include "get_public_key.h"
#include "../globals.h"
#include "../crypto.h"
#include "../ui/display.h"
#include "../helper/send_response.h"

#include "../types/bip32_path.h"

int handler_get_public_key(buffer_t *cdata, bool display, bool address_verification_only) {
    PRINTF("\n.-~=: GET_PUBLIC_KEY called :=~-.\n\n");
    explicit_bzero(&G_context, sizeof(G_context));
    get_public_key_ctx_t *ctx = &G_context.pk_info;
    G_context.req_type = CONFIRM_ADDRESS;
    G_context.state = STATE_NONE;

    cx_ecfp_private_key_t private_key = {0};
    cx_ecfp_public_key_t public_key = {0};

    bip32_path_t *bip32 = &ctx->my_derived_public_key.bip32_path;

    if (!buffer_read_u8(cdata, &bip32->path_len) || !buffer_read_bip32_path(cdata, bip32)) {
        return io_send_sw(SW_WRONG_DATA_LENGTH);
    }

    // derive private key according to BIP32 path
    crypto_derive_private_key_and_chain_code(&private_key, ctx->chain_code, bip32);
    // generate corresponding public key
    crypto_init_and_export_public_key(&private_key, &public_key, ctx->raw_uncompressed_public_key);

    if (!crypto_compress_public_key(&public_key, &ctx->my_derived_public_key.address.public_key)) {
        explicit_bzero(&private_key, sizeof(private_key));

        return io_send_sw(ERR_CMD_GET_PUBLIC_KEY_FAILED_TO_COMPRESS_KEY);
    }
    ctx->my_derived_public_key.address.address_type = RE_ADDRESS_PUBLIC_KEY;

    explicit_bzero(&private_key, sizeof(private_key));

    if (display) {
        return ui_display_address_from_get_pubkey_cmd(&ctx->my_derived_public_key,
                                                      address_verification_only);
    } else {
        return helper_send_response_pubkey();
    }
}
