#include "instruction_type.h"
#include "os.h"

bool is_re_ins_type_known(int raw) {
    return raw <= RE_INSTRUCTION_TYPE_LAST_KNOWN;
}

bool is_re_ins_type_supported(int raw) {
    switch (raw) {
        case INS_DOWN:   // Consuming UTXOs
        case INS_LDOWN:  // Consuming UTXOs
        case INS_UP:     // New substate
        case INS_END:    // Marker for end of substate group ("action")
        case INS_MSG:    // Attached Message
        case INS_HEADER:
        case INS_SYSCALL:
            return true;
    }
    return false;
}

void print_re_ins_type(re_instruction_type_e ins_type) {
    PRINTF("Instruction type: ");
    switch (ins_type) {
        case INS_DOWN:
            PRINTF("'DOWN'");
            break;
        case INS_LDOWN:
            PRINTF("'LDOWN'");
            break;
        case INS_UP:
            PRINTF("'UP'");
            break;
        case INS_END:
            PRINTF("'END'");
            break;
        case INS_MSG:
            PRINTF("'MSG'");
            break;
        case INS_SYSCALL:
            PRINTF("'SYSCALL'");
            break;
        case INS_HEADER:
            PRINTF("'HEADER'");
            break;
        default:
            PRINTF("UNKNOWN instruction type: %d", ins_type);
            break;
    }
    PRINTF("\n");
}

bool have_payload_to_parse(re_instruction_type_e ins_type) {
    switch (ins_type) {
        case INS_DOWN:
        case INS_LDOWN:
        case INS_UP:
        case INS_MSG:
        case INS_SYSCALL:
        case INS_HEADER:
            return true;
        case INS_END:
            return false;
    }
}