#include "init_transaction_parser_config.h"

static bool parse_tx_parser_config_tx_metadata(buffer_t *buffer,
                                               parse_tx_config_outcome_e *outcome,
                                               transaction_metadata_t *metadata,
                                               bip32_path_t *bip32_path) {
    // PARSE BIP32
    if (!buffer_read_u8(buffer, &bip32_path->path_len) ||
        !buffer_read_bip32_path(buffer, bip32_path)) {
        *outcome = PARSE_TX_CONFIG_BIP32_FAILURE;
        return false;
    }

    // PARSE TX size count
    if (!buffer_read_u32(buffer, &metadata->tx_byte_count, BE)) {
        *outcome = PARSE_TX_CONFIG_TX_SIZE_FAILURE;
        return false;
    }
    metadata->tx_bytes_received_count = 0;

    // PARSE instruction count
    if (!buffer_read_u16(buffer, &metadata->total_number_of_instructions, BE)) {
        *outcome = PARSE_TX_CONFIG_INSTRUCTION_COUNT_FAILURE;
        return false;
    }
    metadata->number_of_instructions_received = 0;

    // PARSE OPTIONAL HRP of non native token being transferred.
    if (!buffer_read_u8(buffer, &metadata->hrp_non_native_token_len) ||
        metadata->hrp_non_native_token_len > MAX_BECH32_HRP_PART_LEN ||
        !buffer_move_fill_target(buffer,
                                 (uint8_t *) &metadata->hrp_non_native_token,
                                 metadata->hrp_non_native_token_len)) {
        *outcome = PARSE_TX_CONFIG_OPTIONAL_RRI_HRP_FAILURE;
        return false;
    }

    return true;
}

bool parse_tx_parser_config(buffer_t *buffer,
                            parse_tx_config_outcome_e *outcome,
                            init_transaction_parser_config_t *config) {
    explicit_bzero(config, sizeof(*config));
    if (!parse_tx_parser_config_tx_metadata(buffer,
                                            outcome,
                                            &config->transaction_metadata,
                                            &config->bip32_path)) {
        return false;
    }

    config->instruction_display_config = (const instruction_display_config_t){
        .display_substate_contents = true,
        .display_tx_summary = true,
    };

    return true;
}