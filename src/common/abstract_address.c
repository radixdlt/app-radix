/*******************************************************************************
 *   (c) 2019 Zondax GmbH
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
 ********************************************************************************/

#include "abstract_address.h"

#include "bech32_encode.h"
#include <string.h>  // memset, explicit_bzero

bool abstract_addr_from_bytes(char *hrp,
                              size_t hrp_len,

                              const uint8_t *in,
                              size_t in_len,

                              char *dst,
                              size_t *dst_len) {
    UNUSED(hrp_len);
    explicit_bzero(dst, *dst_len);

    if (in_len > MAX_BECH32_DATA_PART_BYTE_COUNT) {
        PRINTF("bech32 encoding failed, out of bounds.\n");
        return false;
    }

    uint8_t tmp_data[MAX_BECH32_DATA_PART_BYTE_COUNT];
    explicit_bzero(tmp_data, sizeof(tmp_data));

    size_t tmp_size = 0;
    int pad = 1;  // use padding
    convert_bits(tmp_data, &tmp_size, 5, in, in_len, 8, pad);
    if (tmp_size >= *dst_len) {
        PRINTF("bech32 encoding failed, out of bounds.\n");
        return false;
    }

    if (!bech32_encode(dst, hrp, tmp_data, &tmp_size)) {
        PRINTF("bech32 encoding failed, encoding failed.\n");
        return false;
    }
    // Set actual size
    *dst_len = tmp_size;

    return true;
}
