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

#include "sw.h"     // SW_INS_NOT_SUPPORTED
#include "../io.h"  // io_send_sw

int handler_diffie_hellman(buffer_t *cdata, bool display) {
    UNUSED(cdata);
    UNUSED(display);
    PRINTF(
        "DIFFIE_HELLMAN called. It is not implemented yet. Responding with 'SW_INS_NOT_SUPPORTED' "
        "(%d)",
        SW_INS_NOT_SUPPORTED);
    return io_send_sw(SW_INS_NOT_SUPPORTED);
}