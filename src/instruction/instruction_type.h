#pragma once

#include <stdbool.h>

// PREPARED_VALIDATOR_OWNER_UPDATE
#define RE_INSTRUCTION_TYPE_LAST_KNOWN 0x13

typedef enum {
    INS_END = 0x00,
    INS_UP = 0x01,
    INS_DOWN = 0x04,
    INS_LDOWN = 0x05,
    INS_MSG = 0x06,
    INS_SYSCALL = 0x09,
    INS_HEADER = 0x0a,
    INS_VREAD = 0x0d,
    INS_READ = 0x0e,
} re_instruction_type_e;

bool is_re_ins_type_known(int raw);

bool is_re_ins_type_supported(int raw);

bool have_payload_to_parse(re_instruction_type_e ins_type);
