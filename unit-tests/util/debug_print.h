#pragma once

#include "../src/transaction/transaction_parser.h"  // parse_and_process_instruction_outcome_t

void dbg_print_re_ins_type(re_instruction_type_e ins_type);

void dbg_print_parse_process_instruction_outcome(parse_and_process_instruction_outcome_t* outcome);
