#include "instruction_type.h"

bool is_re_ins_type_known(int raw) {
    return raw <= RE_INSTRUCTION_TYPE_LAST_KNOWN;
}

bool is_re_ins_type_supported(int raw) {
    switch (raw) {
        case INS_DOWN:     // Consuming UTXOs
        case INS_LDOWN:    // Consuming UTXOs
        case INS_UP:       // New substate
        case INS_END:      // Marker for end of substate group ("action")
        case INS_MSG:      // Attached Message
        case INS_HEADER:   // Prevent burn/mint of tokens
        case INS_SYSCALL:  // Tx fee
        case INS_VREAD:
        case INS_READ:
            return true;
        default:
            return false;
    }
}

bool have_payload_to_parse(re_instruction_type_e ins_type) {
    switch (ins_type) {
        case INS_DOWN:
        case INS_LDOWN:
        case INS_UP:
        case INS_MSG:
        case INS_SYSCALL:
        case INS_VREAD:
        case INS_READ:
        case INS_HEADER:
            return true;
        case INS_END:
            return false;
        default:
            return false;  // should never happen
    }
}