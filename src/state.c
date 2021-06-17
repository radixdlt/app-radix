#include "state.h"
#include "globals.h"


void G_update_parse_tx_ins_state(parse_tx_ins_state_e new_state) {
    parse_tx_ins_state_e current_state =
        G_context.sign_tx_info.transaction_parser.instruction_parser.state;

    bool valid_transition = false;

    // Parsed new: ready => parsed
    if (current_state == STATE_PARSE_INS_READY_TO_PARSE &&
        new_state == STATE_PARSE_INS_PARSED_INSTRUCTION) {
        valid_transition = true;
    }

    // Parsed new (no need to display): parsed => ready
    if (current_state == STATE_PARSE_INS_PARSED_INSTRUCTION &&
        new_state == STATE_PARSE_INS_READY_TO_PARSE) {
        valid_transition = true;
    }

    // Needs display: parsed => needs approval
    if (current_state == STATE_PARSE_INS_PARSED_INSTRUCTION &&
        new_state == STATE_PARSE_INS_NEEDS_APPROVAL) {
        valid_transition = true;
    }

    // Approved: needs approval => approved
    if (current_state == STATE_PARSE_INS_NEEDS_APPROVAL && new_state == STATE_PARSE_INS_APPROVED) {
        valid_transition = true;
    }

    // Parse next: approved => ready
    if (current_state == STATE_PARSE_INS_APPROVED && new_state == STATE_PARSE_INS_READY_TO_PARSE) {
        valid_transition = true;
    }

    // Parse last: ready => finished
    if (current_state == STATE_PARSE_INS_READY_TO_PARSE &&
        new_state == STATE_PARSE_INS_FINISHED_PARSING_ALL_INS) {
        valid_transition = true;
    }

    if (!valid_transition) {
        // PRINTF("Invalid state transition\n");
        // PRINTF("FROM: ");
        // print_parse_tx_ins_state(current_state);
        // PRINTF("TO: ");
        // print_parse_tx_ins_state(new_state);
        // PRINTF("Considered bad state => abort tx signing");
        
        io_send_sw(ERR_BAD_STATE);
        return;
    }

    G_context.sign_tx_info.transaction_parser.instruction_parser.state = new_state;
}

void G_parse_tx_state_ready_to_parse() {
    G_update_parse_tx_ins_state(STATE_PARSE_INS_READY_TO_PARSE);
}

void G_parse_tx_state_did_parse_new() {
    G_update_parse_tx_ins_state(STATE_PARSE_INS_PARSED_INSTRUCTION);
}

void G_parse_tx_state_ins_needs_approval() {
    G_update_parse_tx_ins_state(STATE_PARSE_INS_NEEDS_APPROVAL);
}

void G_parse_tx_state_did_approve_ins() {
    G_update_parse_tx_ins_state(STATE_PARSE_INS_APPROVED);
}

void G_parse_tx_state_finished_parsing_all() {
    G_update_parse_tx_ins_state(STATE_PARSE_INS_FINISHED_PARSING_ALL_INS);
}