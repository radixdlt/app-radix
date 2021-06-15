#pragma once

#include <stdint.h>  // uint8_t

#include "cx.h"

#include "instruction_type.h"

#include "../types/public_key.h"
#include "substate/substate_id.h"
#include "substate/substate.h"
#include "../types/re_bytes.h"

#define INS_HEADER_REQUIRED_VERSION                           0x00
#define INS_HEADER_FLAG_DISALLOWING_TOKEN_BURN_AND_TOKEN_MINT 0x01

typedef re_bytes_t message_t;

/**
 * Structure the RE instruction `INS_MSG.
 */
typedef struct {
    message_t message;
} re_ins_msg_t;

/**
 * Structure the RE instruction `INS_UP.
 */
typedef struct {
    substate_t substate;
} re_ins_up_t;

/**
 * Structure the RE instruction `INS_LDOWN.
 */
typedef struct {
    uint32_t substate_index;
} re_ins_ldown_t;

/**
 * Structure the RE instruction `INS_DOWN.
 */
typedef struct {
    substate_id_t substate_id;
} re_ins_down_t;

/**
 * Structure the RE instruction `INS_SYSCALL.
 */
typedef struct {
    re_bytes_t call_data;
} re_ins_syscall_t;

/**
 * Structure the RE instruction `INS_HEADER.
 */
typedef struct {
    uint8_t version;
    uint8_t flag;
} re_ins_header_t;

/**
 * Structure for Radix Engine Instruction, as part of Sign transaction context.
 */
typedef struct {
    re_instruction_type_e ins_type;

    union {
        re_ins_msg_t ins_msg;
        re_ins_ldown_t ins_ldown;
        re_ins_down_t ins_down;
        re_ins_up_t ins_up;
        re_ins_syscall_t ins_syscall;
        re_ins_header_t ins_header;
    };  /// payload of non empty supported instructions

} re_instruction_t;

typedef enum {
    PARSE_INS_OK = 0,
    PARSE_INS_FAIL_UNREGOZNIED_INSTRUCTION_TYPE = 1,
    PARSE_INS_FAIL_UNSUPPORTED_INSTRUCTION_TYPE = 2,
    PARSE_INS_FAILED_TO_PARSE_SUBSTATE = 3,
    PARSE_INS_FAILED_TO_PARSE_SUBSTATE_ID = 4,
    PARSE_INS_FAILED_TO_PARSE_SUBSTATE_INDEX = 5,
    PARSE_INS_FAILED_TO_PARSE_MSG = 6,
    PARSE_INS_FAILED_TO_PARSE_SYSCALL = 7,
    PARSE_INS_FAILED_TO_PARSE_HEADER = 8,
    PARSE_INS_INVALID_HEADER = 9,
} parse_instruction_outcome_type_e;

typedef struct {
    parse_instruction_outcome_type_e outcome_type;
    union {
        uint8_t unrecognized_instruction_type_value;
        uint8_t unsupported_instruction_type_value;
        parse_substate_outcome_t substate_failure;
        parse_substate_id_outcome_e substate_id_failure;
        parse_bytes_outcome_e message_failure;
        parse_bytes_outcome_e syscall_failure;
    };
} parse_instruction_outcome_t;

/**
 * @brief Parse an \em instruction in the transaction to sign.
 *
 * Parse a Radix Engine \struct re_instruction_t from the \p buffer. The outcome of the parsing is
 * put in \p outcome, which will contain failure reason if parsing was unsuccessful. If parsing was
 * successful, the outcome is put in \p instruction and return \code true, else \code false.
 *
 * @param[in] buffer A buffer to read instruction data from.
 * @param[out] outcome If parsing was successful: \code OK, else the failure reason, @see
 * parse_instruction_outcome_t.
 * @param[out] tokens if parsing was successful, this contains the parsed \struct re_instruction_t.
 * @return true if parsing was successful.
 * @return false if parsing failed.
 */
bool parse_instruction(buffer_t *buffer,
                       parse_instruction_outcome_t *outcome,
                       re_instruction_t *instruction);

uint16_t status_word_for_failed_to_parse_ins(parse_instruction_outcome_t *failure);

bool does_instruction_need_to_be_displayed(re_instruction_t *instruction,
                                           public_key_t *my_public_key);