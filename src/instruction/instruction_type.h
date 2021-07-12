#pragma once

#include <stdbool.h>

// PREPARED_VALIDATOR_OWNER_UPDATE
#define RE_INSTRUCTION_TYPE_LAST_KNOWN 0x13

typedef enum {
    INS_END = 0x00,
    INS_SYSCALL = 0x01,
    INS_UP = 0x02,
    INS_READ = 0x03,
    //INS_LREAD = 0x04,
    INS_VREAD = 0x05,
    //INS_LVREAD = 0x06,
    INS_DOWN = 0x07,
    INS_LDOWN = 0x08,
    //INS_VDOWN = 0x09,
    //INS_LVDOWN = 0x0a,
    //INS_SIG = 0x0b,
    INS_MSG = 0x0c,
    INS_HEADER = 0x0d,
    //INS_READINDEX = 0x0e,
    //INS_DOWNINDEX = 0x0f,
} re_instruction_type_e;

bool is_re_ins_type_known(int raw);

bool is_re_ins_type_supported(int raw);

bool have_payload_to_parse(re_instruction_type_e ins_type);
