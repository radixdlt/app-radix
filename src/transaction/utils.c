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

#include <stdint.h>   // uint*_t
#include <stdbool.h>  // bool
#include <string.h>   // memmove

#include "types.h"

bool transaction_utils_check_encoding(const uint8_t *message, uint64_t message_len) {
    for (uint64_t i = 0; i < message_len; i++) {
        if (message[i] > 0x7F) {
            return false;
        }
    }

    return true;
}

bool transaction_utils_format_memo(const uint8_t *message,
                                   uint64_t message_len,
                                   char *dst,
                                   uint64_t dst_len) {
    if (message_len > MAX_MSG_LEN || dst_len < message_len + 1) {
        return false;
    }

    memmove(dst, message, message_len);
    dst[message_len] = '\0';

    return true;
}
