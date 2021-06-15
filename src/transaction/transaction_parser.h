#pragma once

#include "os.h"  // cx_sha256_t

#include "signing.h"
#include "transaction_parser_config.h"
#include "instruction_parser.h"
#include "transaction.h"

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
