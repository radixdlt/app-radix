#pragma once

#include "init_transaction_parser_config.h"
#include "instruction_parser.h"
#include "transaction.h"
#include "../types/status_word.h"
#include "../types/signing.h"
#include "../types/buffer.h"
#include "../types/hasher.h"

typedef bool (*derive_my_pubkey_key_fn)(derived_public_key_t *);

typedef enum {
    // Successful
    PARSE_PROCESS_INS_SUCCESS_FINISHED_PARSING_INS,
    PARSE_PROCESS_INS_SUCCESS_FINISHED_PARSING_WHOLE_TRANSACTION,

    // Failure
    PARSE_PROCESS_INS_BAD_STATE,
    PARSE_PROCESS_INS_BYTE_COUNT_MISMATCH,
    PARSE_PROCESS_INS_FAILED_TO_PARSE,
    PARSE_PROCESS_INS_DISABLE_MINT_AND_BURN_FLAG_NOT_SET,
    PARSE_PROCESS_INS_PARSE_TX_FEE_FROM_SYSCALL_FAIL,
    PARSE_PROCESS_INS_LAST_INS_WAS_NOT_INS_END,
} parse_and_process_instruction_outcome_e;

typedef struct {
    parse_and_process_instruction_outcome_e outcome_type;
    union {
        parse_instruction_outcome_t parse_failure;
    };

} parse_and_process_instruction_outcome_t;

/**
 * @brief Parser of transaction to sign.
 *
 */
typedef struct {
    signing_t signing;
    transaction_metadata_t transaction_metadata;
    instruction_display_config_t instruction_display_config;
    instruction_parser_t
        instruction_parser;  /// Parsing of individual instructions in the transaction to sign

    transaction_t transaction;  /// State of parsed transaction so far.
} transaction_parser_t;

bool parse_and_process_instruction_from_buffer(buffer_t *buffer,
                                               transaction_parser_t *tx_parser,
                                               parse_and_process_instruction_outcome_t *outcome);

status_word_t status_word_for_parse_and_process_ins_failure(
    parse_and_process_instruction_outcome_t *failure);

typedef enum {
    INIT_TX_PARSER_OK,
    INIT_TX_PARSER_INVALID_TX_METADATA_IN_CONFIG,
    INIT_TX_PARSER_FAILED_TO_DERIVE_MY_PUBLIC_KEY,
} init_tx_parser_outcome_e;

typedef struct {
    init_tx_parser_outcome_e outcome_type;
} init_tx_parser_outcome_t;

bool init_tx_parser_with_config(transaction_parser_t *tx_parser,
                                derive_my_pubkey_key_fn derive_my_pubkey,
                                sha_256_once_fn sha_256_once,
                                init_implementing_hasher_fn reinit_implementing_hasher,
                                init_transaction_parser_config_t *config,
                                init_tx_parser_outcome_t *outcome);