#pragma once

#include "transaction_metadata.h"
#include "instruction_display_config.h"
#include "../types/bip32_path.h"
#include "../types/buffer.h"

/**
 * @brief Only used for initializing a transaction parser.
 *
 */
typedef struct {
    transaction_metadata_t transaction_metadata;
    instruction_display_config_t instruction_display_config;
    bip32_path_t bip32_path;
} init_transaction_parser_config_t;

typedef enum {
    PARSE_TX_CONFIG_BIP32_FAILURE,
    PARSE_TX_CONFIG_TX_SIZE_FAILURE,
    PARSE_TX_CONFIG_INSTRUCTION_COUNT_FAILURE,
    PARSE_TX_CONFIG_OPTIONAL_RRI_HRP_FAILURE,
} parse_tx_config_outcome_e;

bool parse_tx_parser_config(buffer_t *buffer,
                            parse_tx_config_outcome_e *outcome,
                            init_transaction_parser_config_t *config);