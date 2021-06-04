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

#include <stddef.h>  // size_t
#include <stdint.h>  // uint*_t
#include <string.h>  // memmove

#include "send_response.h"
#include "../constants.h"
#include "../globals.h"
#include "../sw.h"
#include "common/buffer.h"

int helper_send_response_pubkey() {
    uint8_t resp[
        /* One byte specifying length of PubKey */ 1 + PUBLIC_KEY_POINT_LEN +
        /* One byte specifying length of CHAIN_CODE_LEN */ 1 + CHAIN_CODE_LEN] = {0};

    size_t offset = 0;

    resp[offset++] = PUBLIC_KEY_POINT_LEN;
    resp[offset++] = PUBKEY_FLAG_KEY_IS_UNCOMPRESSED;
    memmove(resp + offset,
            G_context.pk_info.raw_uncompressed_public_key,
            PUBLIC_KEY_UNCOMPRESSEED_LEN);
    offset += PUBLIC_KEY_UNCOMPRESSEED_LEN;
    resp[offset++] = CHAIN_CODE_LEN;
    memmove(resp + offset, G_context.pk_info.chain_code, CHAIN_CODE_LEN);
    offset += CHAIN_CODE_LEN;

    return io_send_response(&(const buffer_t){.ptr = resp, .size = offset, .offset = 0}, SW_OK);
}

int helper_send_response_sharedkey() {
    uint8_t resp[
        /* One byte specifying length of PubKey */ 1 + PUBLIC_KEY_POINT_LEN] = {0};
    size_t offset = 0;

    resp[offset++] = PUBLIC_KEY_POINT_LEN;
    memmove(resp + offset, G_context.ecdh_info.shared_pubkey_point, PUBLIC_KEY_POINT_LEN);
    offset += PUBLIC_KEY_POINT_LEN;

    return io_send_response(&(const buffer_t){.ptr = resp, .size = offset, .offset = 0}, SW_OK);
}

int helper_send_response_sig() {
    uint8_t resp[
        /* One byte specifying length of SigLength */ 1 + MAX_DER_SIG_LEN +
        /* One byte for Signature.V */ 1] = {0};

    size_t offset = 0;

    resp[offset++] = G_context.sig_info.signature_len;
    memmove(resp + offset, G_context.sig_info.signature, G_context.sig_info.signature_len);
    offset += G_context.sig_info.signature_len;
    resp[offset++] = (uint8_t) G_context.sig_info.v;

    return io_send_response(&(const buffer_t){.ptr = resp, .size = offset, .offset = 0}, SW_OK);
}