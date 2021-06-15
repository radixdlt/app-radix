#pragma once

#include "parse_tx_ins_state.h"
#include "../instruction/instruction.h"

/**
 * @brief Parser of one instruction inside a transaction.
 *
 */
typedef struct {
    parse_tx_ins_state_e state;
    re_instruction_t instruction;  /// latest parsed Radix Engine instruction
} instruction_parser_t;