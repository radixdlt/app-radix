#pragma once

#include "../common/bech32_encode.h"

typedef struct {
    uint32_t tx_byte_count;            /// Number of bytes in the while transaction to receive.
    uint32_t tx_bytes_received_count;  /// Number of tx bytes received

    uint16_t total_number_of_instructions;     /// Number of Radix Engine instructions to receive.
    uint16_t number_of_instructions_received;  /// Number of Radix Engine instructions that has been
                                               /// received.

    char hrp_non_native_token[MAX_BECH32_HRP_PART_LEN];
    uint8_t hrp_non_native_token_len;

} transaction_metadata_t;