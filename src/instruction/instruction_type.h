#pragma once

#include <stdbool.h>

#define RE_INSTRUCTION_TYPE_LAST_KNOWN 0x0a

typedef enum {
    INS_END = 0x00,
    INS_UP = 0x01,
    // INS_VDOWN = 0x02,       // Unsupported
    // INS_VDOWNARG = 0x03,    // Unsupported
    INS_DOWN = 0x04,
    INS_LDOWN = 0x05,
    INS_MSG = 0x06,
    // INS_SIG = 0x07,         // Unsupported
    // INS_DOWNALL = 0x08,     // Unsupported
    INS_SYSCALL = 0x09,
    INS_HEADER = 0x0a,
} re_instruction_type_e;

bool is_re_ins_type_known(int raw);

bool is_re_ins_type_supported(int raw);

void print_re_ins_type(re_instruction_type_e ins_type);
bool have_payload_to_parse(re_instruction_type_e ins_type);
