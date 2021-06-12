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
#include <stddef.h>   // size_t
#include <string.h>   // memset, explicit_bzero

#include "os.h"
#include "cx.h"

#include "sign_tx.h"

#include "../state.h"
#include "../sw.h"
#include "../globals.h"
#include "../crypto.h"
#include "../ui/display.h"
#include "../common/buffer.h"
#include "../instruction/instruction.h"
#include "../common/bech32_encode.h"
#include "../helper/send_response.h"
#include "../common/read.h"    // read_u16_be, read_u32_be
#include "../common/format.h"  // print_uint256

static void initiate_hasher() {
    cx_sha256_init(&G_context.tx_info.hasher);
}

static void hash(const uint8_t *in, const size_t in_len, bool should_finalize) {
    update_hash(&G_context.tx_info.hasher,
                in,
                in_len,
                should_finalize,
                G_context.sig_info.m_hash,
                HASH_LEN);
}

static int handle_first_metadata_apdu(buffer_t *buffer) {
    explicit_bzero(&G_context, sizeof(G_context));

    // PARSE BIP32
    if (!buffer_read_u8(buffer, &G_context.bip32_path_len) ||
        !buffer_read_bip32_path(buffer, G_context.bip32_path, (size_t) G_context.bip32_path_len)) {
        return io_send_sw(ERR_CMD_SIGN_TX_PARSE_BIP32_PATH_FAILURE);
    }

    // Derive public key according to BIP32 path
    cx_ecfp_private_key_t private_key = {0};
    cx_ecfp_public_key_t public_key = {0};
    crypto_derive_private_key(&private_key,
                              G_context.pk_info.chain_code,
                              G_context.bip32_path,
                              G_context.bip32_path_len);
    // Generate corresponding public key
    crypto_init_public_key(&private_key,
                           &public_key,
                           G_context.pk_info.raw_uncompressed_public_key);
    if (!crypto_compress_public_key(&public_key, &G_context.tx_info.my_public_key)) {
        return io_send_sw(ERR_CMD_SIGN_TX_FAILED_TO_COMPRESS_MY_KEY);
    }
    // Reset private key
    explicit_bzero(&private_key, sizeof(private_key));

    // PARSE TX size count
    PRINTF("Parsing tx size.\n");
    if (!buffer_read_u32(buffer, &G_context.tx_info.tx_byte_count, BE)) {
        return io_send_sw(ERR_CMD_SIGN_TX_PARSE_TX_SIZE_FAILURE);
    }
    G_context.tx_info.tx_bytes_received_count = 0;
    PRINTF("Parsed tx size: #%d bytes.\n", G_context.tx_info.tx_byte_count);

    // PARSE instruction count
    PRINTF("Parsing instruction count.\n");
    if (!buffer_read_u16(buffer, &G_context.tx_info.total_number_of_instructions, BE)) {
        return io_send_sw(ERR_CMD_SIGN_TX_PARSE_INSTRUCTION_COUNT_FAILURE);
    }
    PRINTF("Parsed instruction count: #%d.\n", G_context.tx_info.total_number_of_instructions);
    G_context.tx_info.number_of_instructions_received = 0;

    // PARSE OPTIONAL HRP of non native token being transferred.
    uint8_t hrp_size_len;
    if (!buffer_read_u8(buffer, &hrp_size_len)) {
        return io_send_sw(ERR_CMD_SIGN_TX_PARSE_HRP_LEN_FAILURE);
    }
    if (hrp_size_len > MAX_BECH32_HRP_PART_LEN) {
        return io_send_sw(ERR_CMD_SIGN_TX_PARSE_HRP_TOO_LONG);
    }

    if (!buffer_move_fill_target(buffer,
                                 (uint8_t *) G_context.tx_info.hrp_non_native_token,
                                 hrp_size_len)) {
        return io_send_sw(ERR_CMD_SIGN_TX_PARSE_HRP_FAILED_TO_READ);
    }
    G_context.tx_info.hrp_non_native_token_len = hrp_size_len;

    // SETUP hasher
    initiate_hasher();

    // SETUP state
    G_context.req_type = CONFIRM_TRANSACTION;
    G_context.state = STATE_NONE;

    G_context.tx_info.parse_ins_state = STATE_PARSE_INS_READY_TO_PARSE;

    return io_send_sw(SW_OK);
}

/**
 * @brief Parse transaction fee from SYSCALL instruction.
 *
 * When SYSCALL is used for tx fee, it MUST have length 33, and the first byte (a version byte),
 * MUST be 0x00, and the remaining 32 bytes should be parsed as a UInt256.
 *
 * @param syscall A syscall instruction to parse from.
 * @param tx_fee target uint256 to put result of parsing in
 * @return true if successful
 * @return false if fail
 */
static int parse_tx_fee_from_syscall(re_ins_syscall_t *syscall, uint256_t *tx_fee) {
    PRINTF("Length of SYSCALL data: %d.\n", syscall->call_data.length);
    PRINTF("SYSCALL data: %.*H.\n", syscall->call_data.length, syscall->call_data.data);

    if (syscall->call_data.length != 33) {
        PRINTF(
            "Failed to parse tx fee from syscall, wrong length, requiring length of 33, but got: "
            "%d.\n",
            syscall->call_data.length);
        return false;
    }
    uint8_t required_tx_fee_version_byte = 0x00;
    if (syscall->call_data.data[0] != required_tx_fee_version_byte) {
        PRINTF(
            "Failed to parse tx fee from syscall, incorrect version byte, required: %d, but got: "
            "%d.\n",
            required_tx_fee_version_byte,
            syscall->call_data.data[0]);
        return false;
    }

    readu256BE(syscall->call_data.data + 1, tx_fee);

    return true;
}

static int handle_single_re_ins_apdu(buffer_t *buffer) {
    // Important to reset memory between subsequent instructions.
    explicit_bzero(&G_context.tx_info.instruction, sizeof(G_context.tx_info.instruction));

    // Parse transaction: incoming Radix Engine instructions, one at a time.
    if (G_context.req_type != CONFIRM_TRANSACTION || G_context.state != STATE_NONE ||
        G_context.tx_info.parse_ins_state != STATE_PARSE_INS_READY_TO_PARSE) {
        return io_send_sw(ERR_BAD_STATE);
    }

    G_context.tx_info.tx_bytes_received_count += buffer->size;
    if (G_context.tx_info.tx_bytes_received_count > G_context.tx_info.tx_byte_count) {
        PRINTF("Received more bytes than size of transaction. Bad state => abort signing of tx.");
        return io_send_sw(ERR_BAD_STATE);
    }

    // Parse newly recieved single Radix Engine instruction
    parse_instruction_outcome_t ins_result;
    if (!parse_instruction(buffer, &ins_result, &G_context.tx_info.instruction)) {
        PRINTF("Failed to parse instruction\n");
        uint16_t sw = status_word_for_failed_to_parse_ins(&ins_result);
        return io_send_sw(sw);
    }

    G_context.tx_info.number_of_instructions_received += 1;

    PRINTF("Finished parsing instruction, have now parsed: %d/%d instructions.\n",
           G_context.tx_info.number_of_instructions_received,
           G_context.tx_info.total_number_of_instructions);

    if (G_context.tx_info.instruction.ins_type == INS_HEADER) {
        bool mint_and_burn_is_forbidden = G_context.tx_info.instruction.ins_header.flag ==
                                          INS_HEADER_FLAG_DISALLOWING_TOKEN_BURN_AND_TOKEN_MINT;
        G_context.tx_info.have_asserted_no_mint_or_burn = mint_and_burn_is_forbidden;
    } else {
        // Just finished parsing an instruction that was not INS_HEADER
        if (!G_context.tx_info.have_asserted_no_mint_or_burn) {
            // ☠️  ILLEGAL TX: might burn/mint tokens ☠️
            PRINTF(
                "TX might contain burning or minting of new tokens, but we cannot parse this. This "
                "is considered a fatal error and we abort parsing this tx now, and return an "
                "error.\n");
            return io_send_sw(ERR_CMD_SIGN_TX_DISABLE_MINT_AND_BURN_FLAG_NOT_SET);
        }
    }

    // If instruction is SYSCALL, parse out bytes as transaction fee.
    if (G_context.tx_info.instruction.ins_type == INS_SYSCALL) {
        PRINTF("Parsing tx fee from SYSCALL.\n");

        if (!parse_tx_fee_from_syscall(&G_context.tx_info.instruction.ins_syscall,
                                       &G_context.tx_info.tx_fee)) {
            PRINTF("Failed to parse tx fee from SYSCALL.\n");
            return io_send_sw(ERR_CMD_SIGN_TX_PARSE_TX_FEE_FROM_SYSCALL_FAIL);
        }

        PRINTF("Successfully parsed tx fee:");
        print_uint256(&G_context.tx_info.tx_fee);
        PRINTF("\n");

        // Add tx fee to total cost
        add256(&G_context.tx_info.tx_fee,
               &G_context.tx_info.total_xrd_amount_incl_fee,
               &G_context.tx_info.total_xrd_amount_incl_fee);
    } else if (G_context.tx_info.instruction.ins_up.substate.type == SUBSTATE_TYPE_TOKENS &&
               !public_key_equals(
                   &G_context.tx_info.my_public_key,
                   &G_context.tx_info.instruction.ins_up.substate.tokens.owner.public_key) &&
               G_context.tx_info.instruction.ins_up.substate.tokens.rri.address_type ==
                   RE_ADDRESS_NATIVE_TOKEN) {
        PRINTF("Sending XRD in tokens transfer, will add to total cost:");
        print_uint256(&G_context.tx_info.instruction.ins_up.substate.tokens.amount);
        PRINTF("\n");

        // Spending XRD => increment total XRD spent counter
        add256(&G_context.tx_info.instruction.ins_up.substate.tokens.amount,
               &G_context.tx_info.total_xrd_amount_incl_fee,
               &G_context.tx_info.total_xrd_amount_incl_fee);
    }

    bool was_last_apdu = G_context.tx_info.number_of_instructions_received ==
                         G_context.tx_info.total_number_of_instructions;

    if (was_last_apdu) {
        if (G_context.tx_info.tx_bytes_received_count != G_context.tx_info.tx_byte_count) {
            PRINTF(
                "Number of received bytes does not match number of expected bytes. Bad state => "
                "abort signing of tx. received count: %d, and tx have size: %d\n",
                G_context.tx_info.tx_bytes_received_count,
                G_context.tx_info.tx_byte_count);
            return io_send_sw(ERR_BAD_STATE);
        }

        PRINTF("Finished parsing all instructions.\n");
        G_context.state = STATE_PARSED;
    }

    // Always update the hasher.
    hash(buffer->ptr, buffer->size, was_last_apdu);

    if (was_last_apdu) {
        G_parse_tx_state_finished_parsing_all();
        if (G_context.tx_info.instruction.ins_type != INS_END) {
            PRINTF("Expected last instruction to be 'INS_END' but it was not => abort tx signing.");
            return io_send_sw(ERR_CMD_SIGN_TX_LAST_INSTRUCTION_WAS_NOT_INS_END);
        }

        // The hash to sign is now in `G_context->sig_info->m_hash` (see method `hash` above.)
        PRINTF("Finished parsing all instruction.\n");

        if (!G_context.tx_info.display_tx_summary) {
            PRINTF(
                "You have specified to skip displaying TX summary UI => sign tx hash "
                "immediately.\n");
            if (!crypto_sign_message()) {
                G_context.state = STATE_NONE;
                return io_send_sw(ERR_CMD_SIGN_TX_ECDSA_SIGN_FAIL);
            } else {
                return helper_send_response_signature(true);  // also respond with `hash`: true
            }
        }

        return ui_display_tx_summary();

    } else {
        G_parse_tx_state_did_parse_new();

        // Not done yet => tell host machine to continue sending next RE instruction.
        if (does_instruction_need_to_be_displayed(&G_context.tx_info.instruction,
                                                  &G_context.tx_info.my_public_key)) {
            if (G_context.tx_info.display_substate_contents) {
                PRINTF("Newly parsed instruction needs to be displayed to user.\n");
                G_parse_tx_state_ins_needs_approval();

                return ui_display_instruction();
            } else {
                PRINTF(
                    "You have specified to skip displaying contents of instructions => proceeding "
                    "with parsing next.\n");
            }
        } else {
            PRINTF("Finished with instruction which doesn't need to be displayed.\n");
        }

        G_parse_tx_state_ready_to_parse();

        PRINTF(
            "There are more instructions to parse to parse => telling host machine to send more "
            "instructions.\n");
        return io_send_sw(SW_OK);
    }
}

int handler_sign_tx(buffer_t *cdata, bool is_first_metadata_apdu) {
    if (is_first_metadata_apdu) {
        PRINTF("\n.-~=: SIGN_TX called :=~-.\n\n");
        // First APDU with metadata: parse BIP32 & Radix Engine instructions count
        return handle_first_metadata_apdu(cdata);
    } else {
        return handle_single_re_ins_apdu(cdata);
    }

    return 0;
}
