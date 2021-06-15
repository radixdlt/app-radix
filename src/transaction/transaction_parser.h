#pragma once

#include "os.h"  // cx_sha256_t

#include "signing.h"
#include "transaction_parser_config.h"
#include "instruction_parser.h"
#include "transaction.h"
#include "../types/status_word.h"
#include "../types/uint256.h"
#include "../instruction/instruction.h"  // re_ins_syscall_t

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
    cx_sha256_t hasher;
    signing_t signing;
    transaction_parser_config_t config;  ///
    instruction_parser_t
        instruction_parser;  /// Parsing of individual instructions in the transaction to sign

    transaction_t transaction;  /// State of parsed transaction so far.
} transaction_parser_t;

bool parse_and_process_instruction_from_buffer(buffer_t *buffer,
                                               transaction_parser_t *tx_parser,
                                               parse_and_process_instruction_outcome_t *outcome);

status_word_t status_word_for_parse_and_process_ins_failure(
    parse_and_process_instruction_outcome_t *failure);

void print_parse_process_instruction_outcome(parse_and_process_instruction_outcome_t *outcome);

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
bool parse_tx_fee_from_syscall(re_ins_syscall_t *syscall, uint256_t *tx_fee);