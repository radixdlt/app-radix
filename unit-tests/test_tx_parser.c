#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#include <cmocka.h>

#include "util/sha256.h"
#include "util/debug_print.h"
#include "util/hex_to_bin.h"

#include "types/public_key.h"
#include "types/bip32_path.h"
#include "types/uint256.h"
#include "types/buffer.h"
#include "types/re_bytes.h"
#include "types/re_address.h"
#include "types/derived_public_key.h"
#include "types/hasher.h"

#include "common/read.h"

#include "instruction/substate/tokens.h"
#include "instruction/substate/prepared_stake.h"
#include "instruction/substate/prepared_unstake.h"
#include "instruction/substate/stake_ownership.h"
#include "instruction/substate/validator_allow_delegation_flag.h"
#include "instruction/substate/validator_owner_copy.h"

#include "instruction/substate/substate_type.h"
#include "instruction/substate/substate.h"
#include "instruction/substate/substate_id.h"

#include "instruction/instruction_type.h"

#include "transaction/transaction.h"
#include "transaction/transaction_parser.h"
#include "transaction/transaction_metadata.h"
#include "transaction/instruction_display_config.h"
#include "transaction/init_transaction_parser_config.h"
#include "transaction/instruction_parser.h"

typedef struct {
    char *ins_hex;
    re_instruction_type_e instruction_type;
    /// Iff instruction type is 'INS_UP'
    re_substate_type_e substate_type;
} expected_instruction_t;

static re_substate_type_e IRRELEVANT = (re_substate_type_e) RE_SUBSTATE_TYPE_LAST_KNOWN;

static SHA256_CTX sha256_ctx;

static void init_sha256_hasher() {
    sha256_init(&sha256_ctx);
}

static bool update_sha256_hasher_hash(buffer_t *buf, bool final, uint8_t *out) {
    sha256_update(&sha256_ctx, buf->ptr, buf->size);
    if (final) {
        sha256_final(&sha256_ctx, out);
    }
    return true;  // never fails
}

uint8_t pub_key_bytes[PUBLIC_KEY_COMPRESSED_LEN];

static bool always_derive_44_536_2_1_3(derived_public_key_t *key) {
    key->address.address_type = RE_ADDRESS_PUBLIC_KEY;
    memmove(key->address.public_key.compressed, pub_key_bytes, PUBLIC_KEY_COMPRESSED_LEN);
    return true;
}

typedef struct {
    char *expected_tx_fee;
    char *expected_total_xrd_amount;
    uint8_t expected_hash[HASH_LEN];
    char *my_public_key_hex;  // used to check token transfer change
} expected_success_t;

typedef struct {
    parse_and_process_instruction_outcome_t expected_failure_outcome;
    uint16_t index_of_failing_instruction;

    bool contains_misleading_tx_size_used_to_trigger_failure;
    uint32_t misleading_tx_size_used_to_trigger_failure;
} expected_failure_t;

typedef enum {
    EXPECTED_RESULT_SUCCESS,
    EXPECTED_FAILURE_REASON_SPECIFIC_INSTRUCTION,
} expected_result_e;

typedef struct {
    expected_result_e expected_result;

    uint16_t total_number_of_instructions;
    expected_instruction_t *expected_instructions;

    union {
        expected_success_t expected_success;
        expected_failure_t expected_failure;
    };
} test_vector_t;

void dbg_print_expected_result(expected_result_e expected_result) {
    print_message("Expected result:\n");
    switch (expected_result) {
        case EXPECTED_RESULT_SUCCESS:
            print_message("'SUCCESS'");
            return;
        case EXPECTED_FAILURE_REASON_SPECIFIC_INSTRUCTION:
            print_message("'FAILURE_REASON_SPECIFIC_INSTRUCTION'");
            return;
    }
    print_message("\n");
}

void dbg_print_test_vector(test_vector_t *test_vector) {
    print_message("\nTEST VECTOR:\n");
    dbg_print_expected_result(test_vector->expected_result);
    if (test_vector->expected_result != EXPECTED_RESULT_SUCCESS) {
        print_message("\nExpected failure outcome:\n");
        dbg_print_parse_process_instruction_outcome(
            &test_vector->expected_failure.expected_failure_outcome);

        if (test_vector->expected_result == EXPECTED_FAILURE_REASON_SPECIFIC_INSTRUCTION) {
            print_message("Expected to fail while parsing/processing instruction at index: %d\n",
                          test_vector->expected_failure.index_of_failing_instruction);
        }
    }
    print_message("#instructions: %d\n", test_vector->total_number_of_instructions);
    for (int i = 0; i < test_vector->total_number_of_instructions; i++) {
        print_message("\t");
        expected_instruction_t expected_instruction = test_vector->expected_instructions[i];
        dbg_print_re_ins_type(expected_instruction.instruction_type);
    }
}

static void do_test_parse_tx(test_vector_t test_vector) {
    // dbg_print_test_vector(&test_vector);
    uint16_t total_number_of_instructions = test_vector.total_number_of_instructions;
    bool expected_failure = test_vector.expected_result != EXPECTED_RESULT_SUCCESS;

    if (expected_failure) {
        hex_to_bin("0345497f80cf2c495286a146178bc2ad1a95232a8fce45856c55d67716cda020b9",
                   pub_key_bytes,
                   PUBLIC_KEY_COMPRESSED_LEN);
    } else {
        hex_to_bin(test_vector.expected_success.my_public_key_hex,
                   pub_key_bytes,
                   PUBLIC_KEY_COMPRESSED_LEN);
    }

    size_t i;
    uint32_t tx_byte_count = 0;
    expected_instruction_t *expected_instruction;

    if (expected_failure &&
        test_vector.expected_failure.contains_misleading_tx_size_used_to_trigger_failure) {
        tx_byte_count = test_vector.expected_failure.misleading_tx_size_used_to_trigger_failure;
    } else {
        expected_instruction = test_vector.expected_instructions;

        for (i = 0; i < total_number_of_instructions; i++, expected_instruction++) {
            tx_byte_count += strlen(expected_instruction->ins_hex) / 2;
        }
    }

    char output[UINT256_DEC_STRING_MAX_LENGTH] = {0};
    uint8_t bytes255[255];
    buffer_t buf;

    transaction_parser_t tx_parser;
    memset(&tx_parser, 0, sizeof(tx_parser));

    transaction_metadata_t transaction_metadata = (transaction_metadata_t){
        .tx_byte_count = tx_byte_count,
        .tx_bytes_received_count = (uint32_t) 0,
        .total_number_of_instructions = total_number_of_instructions,
        .number_of_instructions_received = (uint16_t) 0,
        .hrp_non_native_token = {0x00},
        .hrp_non_native_token_len = (uint8_t) 0,
    };

    const bip32_path_t bip32_path = (bip32_path_t){
        .path = {0x8000002C, 0x80000218, 0x80000002, 1, 3},
        .path_len = 5,
    };

    const bool format_bip32_successful = bip32_path_format(&bip32_path, output, sizeof(output));
    assert_true(format_bip32_successful);
    assert_string_equal(output, "44'/536'/2'/1/3");

    instruction_display_config_t ins_display_config = (instruction_display_config_t){
        .display_substate_contents = true,
        .display_tx_summary = true,
    };

    init_transaction_parser_config_t tx_parser_config = (init_transaction_parser_config_t){
        .transaction_metadata = transaction_metadata,
        .instruction_display_config = ins_display_config,
        .bip32_path = bip32_path,
    };

    init_tx_parser_outcome_t init_tx_parser_outcome;

    const bool init_tx_parser_successful = init_tx_parser_with_config(&tx_parser,
                                                                      &always_derive_44_536_2_1_3,
                                                                      &update_sha256_hasher_hash,
                                                                      &init_sha256_hasher,
                                                                      &tx_parser_config,
                                                                      &init_tx_parser_outcome);

    assert_true(init_tx_parser_successful);

    parse_and_process_instruction_outcome_t outcome;
    bool parse_instruction_successful = false;
    re_instruction_type_e parsed_ins_type;
    expected_instruction = test_vector.expected_instructions;

    for (i = 0; i < total_number_of_instructions; i++, expected_instruction++) {
        bool is_last_instruction = i == total_number_of_instructions - 1;
        size_t instruction_size = strlen(expected_instruction->ins_hex) / 2;
        buf.offset = 0;
        buf.size = instruction_size;
        memset(bytes255, 0, sizeof(bytes255));
        hex_to_bin(expected_instruction->ins_hex, bytes255, instruction_size);
        buf.ptr = bytes255;

        // print_message("Printing buffer\n");
        // print_message("Size: %zu\n", buf.size);
        // for (int j = 0; j < buf.size; ++j) {
        //     print_message("%02x", buf.ptr[j]);
        // }
        // print_message("\n");

        memset(&outcome, 0, sizeof(outcome));  // so that we can use `assert_memory_equal`.

        // Try parse and process, might fail, if so we should assert failure matches expected
        // one
        parse_instruction_successful =
            parse_and_process_instruction_from_buffer(&buf, &tx_parser, &outcome);

        // dbg_print_parse_process_instruction_outcome(&outcome);

        bool expect_to_fail_at_this_specific_instruction =
            (test_vector.expected_result == EXPECTED_FAILURE_REASON_SPECIFIC_INSTRUCTION) &&
            (i == test_vector.expected_failure.index_of_failing_instruction);

        // print_error("\n#### Checking at instruction: %ld\n", i);
        if (expected_failure && expect_to_fail_at_this_specific_instruction) {
            // Should not have succeeded to parse or process since we expected failure.
            assert_false(parse_instruction_successful);

            // Assert we know the failure reason
            assert_int_equal(outcome.outcome_type,
                             test_vector.expected_failure.expected_failure_outcome.outcome_type);

            // Assert we know the underlying failure reason
            assert_memory_equal(&outcome,
                                &test_vector.expected_failure.expected_failure_outcome,
                                sizeof(outcome));

            // Done parsing failure.
            return;
        } else {
            // Even though we might expect failure when parsing/processing some instruction in
            // the transaction we are not there yet, or we expect the whole tx to be valid.
            assert_true(parse_instruction_successful);

            if (is_last_instruction) {
                // Last
                assert_int_equal(outcome.outcome_type,
                                 PARSE_PROCESS_INS_SUCCESS_FINISHED_PARSING_WHOLE_TRANSACTION);
            } else {
                assert_int_equal(outcome.outcome_type,
                                 PARSE_PROCESS_INS_SUCCESS_FINISHED_PARSING_INS);

                parsed_ins_type = tx_parser.instruction_parser.instruction.ins_type;

                assert_int_equal(parsed_ins_type, expected_instruction->instruction_type);
                if (parsed_ins_type == INS_UP) {
                    re_substate_type_e parsed_substate_type =
                        tx_parser.instruction_parser.instruction.ins_up.substate.type;
                    assert_int_equal(parsed_substate_type, expected_instruction->substate_type);
                }
            }
        }
    }

    transaction_t transaction = tx_parser.transaction;

    // Must not allow burning/minting
    assert_true(transaction.have_asserted_no_mint_or_burn);

    char *expected_tx_fee = test_vector.expected_success.expected_tx_fee;
    char *expected_total_xrd_amount = test_vector.expected_success.expected_total_xrd_amount;
    uint8_t *expected_hash = test_vector.expected_success.expected_hash;

    //    uint8_t *actual_hash = tx_parser.signing.hasher.hash;
    //    print_error("### Actual hash:\n");
    //    for (int k = 0; k < HASH_LEN; k++) {
    //        print_error("0x%02x, ", actual_hash[k]);
    //        if ((k + 1) % 8 == 0) {
    //            print_error("\n");
    //        }
    //    }

    // Assert hash
    assert_memory_equal(tx_parser.signing.hasher.hash, expected_hash, HASH_LEN);

    // Assert Tx fee
    memset(output, 0, sizeof(output));
    bool uint256_format_success = false;
    uint256_format_success = to_string_uint256(&transaction.tx_fee, output, sizeof(output));
    assert_true(uint256_format_success);
    assert_string_equal(output, expected_tx_fee);

    // Assert total_xrd_amount_incl_fee
    memset(output, 0, sizeof(output));
    uint256_format_success =
        to_string_uint256(&transaction.total_xrd_amount_incl_fee, output, sizeof(output));
    assert_true(uint256_format_success);
    assert_string_equal(output, expected_total_xrd_amount);
}

static void test_failure_missing_header(void **state) {
    (void) state;

    expected_instruction_t expected_instructions[] = {
        // Missing header
        {
            .ins_hex = "074b95e6aa95cae5010419b986e8913a5c9628647b0ea21d977dc96c4baa4ef2d200000001",
            .instruction_type = INS_DOWN,
            .substate_type = IRRELEVANT,
        },
        {
            .ins_hex = "01002100000000000000000000000000000000000000000000000000000000000000fade",
            .instruction_type = INS_SYSCALL,
            .substate_type = IRRELEVANT,
        },
        {
            .ins_hex = "02000006000402935deebcad35bcf27d05b431276be8fcba26312cd1d54c33ac6748a72fe42"
                       "7ca010000000000000000000000000000000000000000000000000de0b6b3a7640000",
            .instruction_type = INS_UP,
            .substate_type = SUBSTATE_TYPE_TOKENS,
        },
        {
            .ins_hex = "00",
            .instruction_type = INS_END,
            .substate_type = IRRELEVANT,
        },

    };

    test_vector_t test_vector = (test_vector_t){
        .total_number_of_instructions = 4,
        .expected_instructions = expected_instructions,
        .expected_result = EXPECTED_FAILURE_REASON_SPECIFIC_INSTRUCTION,
        .expected_failure =
            {
                .expected_failure_outcome =
                    {
                        .outcome_type = PARSE_PROCESS_INS_DISABLE_MINT_AND_BURN_FLAG_NOT_SET,
                    },
                .index_of_failing_instruction = 0,
            },
    };

    do_test_parse_tx(test_vector);
}

static void test_failure_invalid_header_invalid_version(void **state) {
    (void) state;

    expected_instruction_t expected_instructions[] = {
        {
            // invalid ins_hex, invalid version byte 0xff instead of valid 0x00 (second
            // byte, "flag" byte is valid though)
            .ins_hex = "0dff01",
            .instruction_type = INS_HEADER,
            .substate_type = IRRELEVANT,
        },
        {
            .ins_hex = "00",
            .instruction_type = INS_END,
            .substate_type = IRRELEVANT,
        },
    };

    // clang-format off
    test_vector_t test_vector = (test_vector_t){
        .total_number_of_instructions = 2,
        .expected_instructions = expected_instructions,
        .expected_result = EXPECTED_FAILURE_REASON_SPECIFIC_INSTRUCTION,
        .expected_failure = {
            .expected_failure_outcome = {
                .outcome_type = PARSE_PROCESS_INS_FAILED_TO_PARSE,
                .parse_failure = {
                    .outcome_type = PARSE_INS_INVALID_HEADER,
                 }
            },
            .index_of_failing_instruction = 0,
        },
    };
    // clang-format on

    do_test_parse_tx(test_vector);
}

static void test_failure_invalid_header_invalid_flag(void **state) {
    (void) state;

    expected_instruction_t expected_instructions[] = {
        {
            // invalid ins_hex, invalid "flag" byte: 0x02 instead of valid 0x01 ("version"
            // byte is valid though.)
            .ins_hex = "0d0002",
            .instruction_type = INS_HEADER,
            .substate_type = IRRELEVANT,
        },
        {
            .ins_hex = "00",
            .instruction_type = INS_END,
            .substate_type = IRRELEVANT,
        },
    };

    test_vector_t test_vector = (test_vector_t){
        .total_number_of_instructions = 2,
        .expected_instructions = expected_instructions,
        .expected_result = EXPECTED_FAILURE_REASON_SPECIFIC_INSTRUCTION,
        .expected_failure = {
            .index_of_failing_instruction = 0,
            .expected_failure_outcome = {.outcome_type = PARSE_PROCESS_INS_FAILED_TO_PARSE,
                                         .parse_failure = {
                                             .outcome_type = PARSE_INS_INVALID_HEADER,
                                         }}}};

    do_test_parse_tx(test_vector);
}

static void test_failure_no_fee_in_tx(void **state) {
    (void) state;

    // This tx lacks the SYSCALL instruction, containing the tx fee.
    expected_instruction_t expected_instructions[] = {
        {
            .ins_hex = "0d0001",
            .instruction_type = INS_HEADER,
            .substate_type = IRRELEVANT,
        },
        {
            .ins_hex = "02000006000402935deebcad35bcf27d05b431276be8fcba26312cd1d54c33ac6748a72fe42"
                       "7ca010000000000000000000000000000000000000000000000000de0b6b3a7640000",
            .instruction_type = INS_UP,
            .substate_type = SUBSTATE_TYPE_TOKENS,
        },
        {
            .ins_hex = "00",
            .instruction_type = INS_END,
            .substate_type = IRRELEVANT,
        },
    };

    uint16_t total_number_of_instructions = 3;

    test_vector_t test_vector = (test_vector_t){
        .total_number_of_instructions = total_number_of_instructions,
        .expected_instructions = expected_instructions,
        .expected_result = EXPECTED_FAILURE_REASON_SPECIFIC_INSTRUCTION,
        .expected_failure = {
            .expected_failure_outcome =
                {
                    .outcome_type = PARSE_PROCESS_INS_TX_DOES_NOT_CONTAIN_TX_FEE,
                },
            .index_of_failing_instruction =
                total_number_of_instructions - 1,  // will not fail until last INS has been parsed.
        }};

    do_test_parse_tx(test_vector);
}

static void test_failure_invalid_syscall_too_few_bytes(void **state) {
    (void) state;

    // This tx contains an invalid SYSCALL instruction => fail to parse tx fee
    expected_instruction_t expected_instructions[] = {
        {
            .ins_hex = "0d0001",
            .instruction_type = INS_HEADER,
            .substate_type = IRRELEVANT,
        },
        {
            .ins_hex = "074b95e6aa95cae5010419b986e8913a5c9628647b0ea21d977dc96c4baa4ef2d200000001",
            .instruction_type = INS_DOWN,
            .substate_type = IRRELEVANT,
        },
        {
            .ins_hex = "01000107",
            .instruction_type = INS_SYSCALL,
            .substate_type = IRRELEVANT,
        },
        {
            .ins_hex = "02000006000402935deebcad35bcf27d05b431276be8fcba26312cd1d54c33ac6748a72fe42"
                       "7ca010000000000000000000000000000000000000000000000000de0b6b3a7640000",
            .instruction_type = INS_UP,
            .substate_type = SUBSTATE_TYPE_TOKENS,
        },
        {
            .ins_hex = "00",
            .instruction_type = INS_END,
            .substate_type = IRRELEVANT,
        },
    };

    test_vector_t test_vector = (test_vector_t){
        .total_number_of_instructions = 5,
        .expected_instructions = expected_instructions,
        .expected_result = EXPECTED_FAILURE_REASON_SPECIFIC_INSTRUCTION,
        .expected_failure = {.index_of_failing_instruction = 2,
                             .expected_failure_outcome = {
                                 .outcome_type = PARSE_PROCESS_INS_PARSE_TX_FEE_FROM_SYSCALL_FAIL,
                             }}};

    do_test_parse_tx(test_vector);
}

static void test_failure_claiming_tx_is_larger_than_sum_of_instruction_byte_count(void **state) {
    (void) state;

    expected_instruction_t expected_instructions[] = {
        {
            .ins_hex = "0d0001",
            .instruction_type = INS_HEADER,
            .substate_type = IRRELEVANT,
        },
        {
            .ins_hex = "01002100000000000000000000000000000000000000000000000000000000000000fade",
            .instruction_type = INS_SYSCALL,
            .substate_type = IRRELEVANT,
        },
        {
            .ins_hex = "00",
            .instruction_type = INS_END,
            .substate_type = IRRELEVANT,
        },
    };

    uint16_t total_number_of_instructions = 3;

    test_vector_t test_vector = (test_vector_t){
        .total_number_of_instructions = total_number_of_instructions,
        .expected_instructions = expected_instructions,
        .expected_result = EXPECTED_FAILURE_REASON_SPECIFIC_INSTRUCTION,
        .expected_failure = {
            .contains_misleading_tx_size_used_to_trigger_failure = true,
            .misleading_tx_size_used_to_trigger_failure =
                123456789,  // we mislead here, actual size is 39 bytes.
            .index_of_failing_instruction = total_number_of_instructions - 1,  // fail at last
            .expected_failure_outcome = {
                .outcome_type = PARSE_PROCESS_INS_BYTE_COUNT_MISMATCH,
            }}};

    do_test_parse_tx(test_vector);
}

static void test_failure_claiming_tx_is_smaller_than_sum_of_instruction_byte_count(void **state) {
    (void) state;

    expected_instruction_t expected_instructions[] = {
        {
            .ins_hex = "0d0001",
            .instruction_type = INS_HEADER,
            .substate_type = IRRELEVANT,
        },
        {
            .ins_hex = "01002100000000000000000000000000000000000000000000000000000000000000fade",
            .instruction_type = INS_SYSCALL,
            .substate_type = IRRELEVANT,
        },
        {
            .ins_hex = "00",
            .instruction_type = INS_END,
            .substate_type = IRRELEVANT,
        },
    };

    test_vector_t test_vector = (test_vector_t){
        .total_number_of_instructions = 3,
        .expected_instructions = expected_instructions,
        .expected_result = EXPECTED_FAILURE_REASON_SPECIFIC_INSTRUCTION,
        .expected_failure = {
            .contains_misleading_tx_size_used_to_trigger_failure = true,
            .misleading_tx_size_used_to_trigger_failure =
                5,  // we mislead here, actual size is 39 bytes.
            .index_of_failing_instruction =
                1,  // fail at second, because already after second we have parsed too many bytes.
            .expected_failure_outcome = {
                .outcome_type = PARSE_PROCESS_INS_BYTE_COUNT_MISMATCH,
            }}};

    do_test_parse_tx(test_vector);
}

static void test_failure_unrecognized_instruction(void **state) {
    (void) state;

    expected_instruction_t expected_instructions[] = {
        {
            .ins_hex = "0d0001",
            .instruction_type = INS_HEADER,
            .substate_type = IRRELEVANT,
        },
        {
            .ins_hex = "074b95e6aa95cae5010419b986e8913a5c9628647b0ea21d977dc96c4baa4ef2d200000001",
            .instruction_type = INS_DOWN,
            .substate_type = IRRELEVANT,
        },
        {
            .ins_hex = "01002100000000000000000000000000000000000000000000000000000000000000fade",
            .instruction_type = INS_SYSCALL,
            .substate_type = IRRELEVANT,
        },
        {
            .ins_hex = "ff",
            .instruction_type = 0xff,
            .substate_type = IRRELEVANT,
        },
        {
            .ins_hex = "00",
            .instruction_type = INS_END,
            .substate_type = IRRELEVANT,
        },
    };

    test_vector_t test_vector = (test_vector_t){
        .total_number_of_instructions = 5,
        .expected_instructions = expected_instructions,
        .expected_result = EXPECTED_FAILURE_REASON_SPECIFIC_INSTRUCTION,
        .expected_failure = {.index_of_failing_instruction = 3,
                             .expected_failure_outcome = {
                                 .outcome_type = PARSE_PROCESS_INS_FAILED_TO_PARSE,
                                 .parse_failure = {
                                     .outcome_type = PARSE_INS_FAIL_UNRECOGNIZED_INSTRUCTION_TYPE,
                                     .unrecognized_instruction_type_value = 0xff,
                                 }}}};

    do_test_parse_tx(test_vector);
}

static void test_failure_extra_bytes_after_instruction(void **state) {
    (void) state;

    expected_instruction_t expected_instructions[] = {
        {
            .ins_hex = "0d0001",
            .instruction_type = INS_HEADER,
            .substate_type = IRRELEVANT,
        },
        {
            .ins_hex =
                "07a0686a487f9d3adf4892a358e4460cda432068f069e5e9f4c815af21bc3dd1d60000000001",
            .instruction_type = INS_DOWN,
            .substate_type = IRRELEVANT,
        },
    };

    test_vector_t test_vector = (test_vector_t){
        .total_number_of_instructions = 2,
        .expected_instructions = expected_instructions,
        .expected_result = EXPECTED_FAILURE_REASON_SPECIFIC_INSTRUCTION,
        .expected_failure = {
            .index_of_failing_instruction = 1,
            .expected_failure_outcome = {.outcome_type = PARSE_PROCESS_INS_FAILED_TO_PARSE,
                                         .parse_failure = {
                                             .outcome_type = PARSE_INS_CONTAINS_EXTRA_BYTES,
                                         }}}};

    do_test_parse_tx(test_vector);
}

static void test_failure_unsupported_instruction(char *unsupported_as_hex) {
    uint8_t unsupported_instruction;
    hex_to_bin(unsupported_as_hex, &unsupported_instruction, 1);

    expected_instruction_t expected_instructions[] = {
        {
            .ins_hex = "0d0001",
            .instruction_type = INS_HEADER,
            .substate_type = IRRELEVANT,
        },
        {
            .ins_hex = "074b95e6aa95cae5010419b986e8913a5c9628647b0ea21d977dc96c4baa4ef2d200000001",
            .instruction_type = INS_DOWN,
            .substate_type = IRRELEVANT,
        },
        {
            .ins_hex = "01002100000000000000000000000000000000000000000000000000000000000000fade",
            .instruction_type = INS_SYSCALL,
            .substate_type = IRRELEVANT,
        },
        {
            .ins_hex = unsupported_as_hex,
            .instruction_type = unsupported_instruction,
            .substate_type = IRRELEVANT,
        },
        {
            .ins_hex = "00",
            .instruction_type = INS_END,
            .substate_type = IRRELEVANT,
        },
    };

    test_vector_t test_vector = (test_vector_t){
        .total_number_of_instructions = 5,
        .expected_instructions = expected_instructions,
        .expected_result = EXPECTED_FAILURE_REASON_SPECIFIC_INSTRUCTION,
        .expected_failure = {.index_of_failing_instruction = 3,
                             .expected_failure_outcome = {
                                 .outcome_type = PARSE_PROCESS_INS_FAILED_TO_PARSE,
                                 .parse_failure = {
                                     .outcome_type = PARSE_INS_FAIL_UNSUPPORTED_INSTRUCTION_TYPE,
                                     .unsupported_instruction_type_value = unsupported_instruction,
                                 }}}};

    do_test_parse_tx(test_vector);
}

static void test_failure_unsupported_instruction_lread_0x04(void **state) {
    (void) state;
    test_failure_unsupported_instruction("04");
}

static void test_failure_unsupported_instruction_lvread_0x06(void **state) {
    (void) state;
    test_failure_unsupported_instruction("06");
}

static void test_failure_unsupported_instruction_vdown_0x09(void **state) {
    (void) state;
    test_failure_unsupported_instruction("09");
}

static void test_failure_unsupported_instruction_lvdown_0x0a(void **state) {
    (void) state;
    test_failure_unsupported_instruction("0a");
}

static void test_failure_unsupported_instruction_readindex_0x0e(void **state) {
    (void) state;
    test_failure_unsupported_instruction("0e");
}

static void test_failure_unsupported_instruction_downindex_0x0f(void **state) {
    (void) state;
    test_failure_unsupported_instruction("0f");
}

static void test_failure_unrecognized_substate_type(void **state) {
    (void) state;

    expected_instruction_t expected_instructions[] = {
        {
            .ins_hex = "0d0001",
            .instruction_type = INS_HEADER,
            .substate_type = IRRELEVANT,
        },
        {
            .ins_hex = "074b95e6aa95cae5010419b986e8913a5c9628647b0ea21d977dc96c4baa4ef2d200000001",
            .instruction_type = INS_DOWN,
            .substate_type = IRRELEVANT,
        },
        {
            .ins_hex = "01002100000000000000000000000000000000000000000000000000000000000000fade",
            .instruction_type = INS_SYSCALL,
            .substate_type = IRRELEVANT,
        },
        {
            .ins_hex = "020001ff",  // 0x02 is INS_UP, and 0xff is an unrecognized substate type
            .instruction_type = INS_UP,
            .substate_type = 0xff,  // Unrecognized
        },
        {
            .ins_hex = "00",
            .instruction_type = INS_END,
            .substate_type = IRRELEVANT,
        },
    };

    test_vector_t test_vector = (test_vector_t){
        .total_number_of_instructions = 5,
        .expected_instructions = expected_instructions,
        .expected_result = EXPECTED_FAILURE_REASON_SPECIFIC_INSTRUCTION,
        .expected_failure = {
            .index_of_failing_instruction = 3,
            .expected_failure_outcome = {
                .outcome_type = PARSE_PROCESS_INS_FAILED_TO_PARSE,
                .parse_failure = {
                    .outcome_type = PARSE_INS_FAILED_TO_PARSE_SUBSTATE,
                    .substate_failure =
                        {
                            .outcome_type = PARSE_SUBSTATE_FAIL_UNRECOGNIZED_SUBSTATE_TYPE,
                            .unrecognized_substate_type_value = 0xff,
                        },
                }}}};

    do_test_parse_tx(test_vector);
}

static void test_failure_unsupported_substate_type(char *unsupported_ins_as_hex) {
    uint8_t unsupported_substate;
    hex_to_bin(unsupported_ins_as_hex + strlen(unsupported_ins_as_hex) - 2,
               &unsupported_substate,
               1);

    expected_instruction_t expected_instructions[] = {
        {
            .ins_hex = "0d0001",
            .instruction_type = INS_HEADER,
            .substate_type = IRRELEVANT,
        },
        {
            .ins_hex = "074b95e6aa95cae5010419b986e8913a5c9628647b0ea21d977dc96c4baa4ef2d200000001",
            .instruction_type = INS_DOWN,
            .substate_type = IRRELEVANT,
        },
        {
            .ins_hex = "01002100000000000000000000000000000000000000000000000000000000000000fade",
            .instruction_type = INS_SYSCALL,
            .substate_type = IRRELEVANT,
        },
        {
            .ins_hex = unsupported_ins_as_hex,
            .instruction_type = INS_UP,
            .substate_type = unsupported_substate,
        },
        {
            .ins_hex = "00",
            .instruction_type = INS_END,
            .substate_type = IRRELEVANT,
        },
    };

    test_vector_t test_vector = (test_vector_t){
        .total_number_of_instructions = 5,
        .expected_instructions = expected_instructions,
        .expected_result = EXPECTED_FAILURE_REASON_SPECIFIC_INSTRUCTION,
        .expected_failure = {
            .index_of_failing_instruction = 3,
            .expected_failure_outcome = {
                .outcome_type = PARSE_PROCESS_INS_FAILED_TO_PARSE,
                .parse_failure = {
                    .outcome_type = PARSE_INS_FAILED_TO_PARSE_SUBSTATE,
                    .substate_failure =
                        {
                            .outcome_type = PARSE_SUBSTATE_FAIL_UNSUPPORTED_SUBSTATE_TYPE,
                            .unsupported_substate_type_value = unsupported_substate,
                        },
                }}}};

    do_test_parse_tx(test_vector);
}

static void test_failure_unsupported_substate_type_0x00(void **state) {
    (void) state;
    test_failure_unsupported_substate_type("02000000");
}

static void test_failure_unsupported_substate_type_0x01(void **state) {
    (void) state;
    test_failure_unsupported_substate_type("02000001");
}

static void test_failure_unsupported_substate_type_0x02(void **state) {
    (void) state;
    test_failure_unsupported_substate_type("02000002");
}

static void test_failure_unsupported_substate_type_0x03(void **state) {
    (void) state;
    test_failure_unsupported_substate_type("02000003");
}

static void test_failure_unsupported_substate_type_0x04(void **state) {
    (void) state;
    test_failure_unsupported_substate_type("02000004");
}

static void test_failure_unsupported_substate_type_0x05(void **state) {
    (void) state;
    test_failure_unsupported_substate_type("02000005");
}

static void test_failure_unsupported_substate_type_0x0a(void **state) {
    (void) state;
    test_failure_unsupported_substate_type("0200000a");
}

static void test_failure_unsupported_substate_type_0x0b(void **state) {
    (void) state;
    test_failure_unsupported_substate_type("0200000b");
}

static void test_failure_unsupported_substate_type_0x0c(void **state) {
    (void) state;
    test_failure_unsupported_substate_type("0200000c");
}

static void test_failure_unsupported_substate_type_0x0d(void **state) {
    (void) state;
    test_failure_unsupported_substate_type("0200000d");
}

static void test_failure_unsupported_substate_type_0x0f(void **state) {
    (void) state;
    test_failure_unsupported_substate_type("0200000f");
}

static void test_failure_unsupported_substate_type_0x10(void **state) {
    (void) state;
    test_failure_unsupported_substate_type("02000010");
}

static void base_test_failure_parse_token(parse_tokens_outcome_t tokens_failure,
                                          char *ins_hex_invalid_up_tokens) {
    expected_instruction_t expected_instructions[] = {
        {
            .ins_hex = "0d0001",
            .instruction_type = INS_HEADER,
            .substate_type = IRRELEVANT,
        },
        {
            .ins_hex = "07c1e268b8b61ce5688d039aefa1e5ea6612a6c4d3b497713582916b533d6c502800000003",
            .instruction_type = INS_DOWN,
            .substate_type = IRRELEVANT,
        },
        {
            .ins_hex = "010021000000000000000000000000000000000000000000000038821089088b6063da18",
            .instruction_type = INS_SYSCALL,
            .substate_type = IRRELEVANT,
        },
        {
            .ins_hex = ins_hex_invalid_up_tokens,
            .instruction_type = INS_UP,
            .substate_type = SUBSTATE_TYPE_TOKENS,
        },
        {
            .ins_hex = "00",
            .instruction_type = INS_END,
            .substate_type = IRRELEVANT,
        },
    };

    test_vector_t test_vector = (test_vector_t){
        .total_number_of_instructions = 5,
        .expected_instructions = expected_instructions,
        .expected_result = EXPECTED_FAILURE_REASON_SPECIFIC_INSTRUCTION,
        .expected_failure = {.index_of_failing_instruction = 3,
                             .expected_failure_outcome = {
                                 .outcome_type = PARSE_PROCESS_INS_FAILED_TO_PARSE,
                                 .parse_failure = {
                                     .outcome_type = PARSE_INS_FAILED_TO_PARSE_SUBSTATE,
                                     .substate_failure =
                                         {
                                             .outcome_type = PARSE_SUBSTATE_FAILED_TO_PARSE_TOKENS,
                                             .tokens_failure = tokens_failure,
                                         },
                                 }}}};

    do_test_parse_tx(test_vector);
}

static void base_test_failure_parse_tokens_invalid_resource(
    parse_address_failure_reason_e underlying_rri_failure,
    char *ins_hex_invalid_up_tokens) {
    base_test_failure_parse_token(
        (parse_tokens_outcome_t){
            .outcome_type = PARSE_TOKENS_FAILURE_PARSE_RESOURCE,
            .resource_parse_failure_reason = underlying_rri_failure,
        },
        ins_hex_invalid_up_tokens);
}

static void test_failure_parse_tokens_invalid_resource_unrecognized_address_type_0xff(
    void **state) {
    (void) state;
    // 01=INS_UP, 05=TOKENS, 00=RESERVED,
    // OWNER=0402935deebcad35bcf27d05b431276be8fcba26312cd1d54c33ac6748a72fe427ca, ff=specifying an
    // unrecognized Address Type value of 0xff
    base_test_failure_parse_tokens_invalid_resource(
        PARSE_ADDRESS_FAIL_UNRECOGNIZED_ADDRESS_TYPE,
        "02000006000402935deebcad35bcf27d05b431276be8fcba26312cd1d54c33ac6748a72fe427caff");
}

static void test_failure_parse_tokens_invalid_resource_usupported_address_type_system_0x00(
    void **state) {
    (void) state;
    // 01=INS_UP, 05=TOKENS, 00=RESERVED,
    // OWNER=0402935deebcad35bcf27d05b431276be8fcba26312cd1d54c33ac6748a72fe427ca, 00=specifying an
    // unsupported Address Type value of 0x00 (RE_ADDRESS_SYSTEM).
    base_test_failure_parse_tokens_invalid_resource(
        PARSE_ADDRESS_FAIL_UNSUPPORTED_ADDRESS_TYPE,
        "02000006000402935deebcad35bcf27d05b431276be8fcba26312cd1d54c33ac6748a72fe427ca00");
}

static void test_failure_parse_tokens_invalid_resource_hashed_key_too_short(void **state) {
    (void) state;
    // 01=INS_UP, 05=TOKENS, 00=RESERVED,
    // OWNER=0402935deebcad35bcf27d05b431276be8fcba26312cd1d54c33ac6748a72fe427ca, 03=specifying an
    // HashedKeyNonce and `0xff` being just one byte instead of expected 26 bytes => too short.
    base_test_failure_parse_tokens_invalid_resource(
        PARSE_ADDRESS_FAIL_HASHEDKEY_NOT_ENOUGH_BYTES,
        "02000006000402935deebcad35bcf27d05b431276be8fcba26312cd1d54c33ac6748a72fe427ca03ff");
}

static void test_failure_parse_tokens_invalid_resource_incompatible_address_type(void **state) {
    (void) state;
    // 01=INS_UP, 05=TOKENS, 00=RESERVED,
    // OWNER=0402935deebcad35bcf27d05b431276be8fcba26312cd1d54c33ac6748a72fe427ca, 04=fspecifying an
    // PublicKey, which is incompatible with RRI.
    base_test_failure_parse_tokens_invalid_resource(
        PARSED_ADDRESS_FAIL_EXPECTED_TYPE_COMPATIBLE_WITH_RESOURCE,
        "02000006000402935deebcad35bcf27d05b431276be8fcba26312cd1d54c33ac6748a72fe427ca040345497f80"
        "cf2c495286a146178bc2ad1a95232a8fce45856c55d67716cda020b9");
}

static void base_test_failure_parse_tokens_invalid_owner(
    parse_address_failure_reason_e underlying_owner_failure,
    char *ins_hex_invalid_up_tokens) {
    base_test_failure_parse_token(
        (parse_tokens_outcome_t){
            .outcome_type = PARSE_TOKENS_FAILURE_PARSE_OWNER,
            .owner_parse_failure_reason = underlying_owner_failure,
        },
        ins_hex_invalid_up_tokens);
}

static void test_failure_parse_tokens_invalid_owner_address_type_0x01_system(void **state) {
    (void) state;
    base_test_failure_parse_tokens_invalid_owner(
        PARSE_ADDRESS_FAIL_UNSUPPORTED_ADDRESS_TYPE,
        "0200020600"  // valid start of tokens:  02=INS_UP, 0002=SIZE, 06=TOKENS, 00=RESERVED,
        "00"  // specifying RE_ADDRESS_SYSTEM (used for RRI), which is invalid for account address
    );
}

static void test_failure_parse_tokens_invalid_owner_address_type_0x03_hashed_pubkey(void **state) {
    (void) state;
    base_test_failure_parse_tokens_invalid_owner(
        PARSED_ADDRESS_FAIL_EXPECTED_TYPE_COMPATIBLE_ACCOUNT_OR_VALIDATOR_ADDRESS,
        "0200020600"  // valid start of tokens:  01=INS_UP, 05=TOKENS, 00=RESERVED,
        "03ababdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"  // specifying
                                                                  // RE_ADDRESS_HASHED_KEY
                                                                  // (used for RRI), which is
                                                                  // invalid for account address
    );
}

static void test_failure_parse_tokens_invalid_owner_too_few_bytes(void **state) {
    (void) state;
    base_test_failure_parse_tokens_invalid_owner(
        PARSE_ADDRESS_FAIL_PUBKEY_NOT_ENOUGH_BYTES,
        "020002060004"  // valid start of tokens:  02=INS_UP, 06=TOKENS, 00=RESERVED,
        "04ff");        // valid type, but too few bytes
}

static void base_test_rri_format_hrp(char *hashed_key_hex,
                                     char *hrp,
                                     const size_t hrp_len,
                                     char *expected_rri) {
    re_address_t address = (re_address_t){
        .address_type = RE_ADDRESS_HASHED_KEY_NONCE,
        .hashed_key = {0},
    };
    hex_to_bin(hashed_key_hex, address.hashed_key, RE_ADDR_HASHED_KEY_LEN);

    char out[150];
    memset(out, 0, sizeof(out));

    bool success = format_other_token_from_re_address(&address, hrp, hrp_len, out, sizeof(out));
    assert_true(success);
    assert_string_equal(out, expected_rri);
}

static void base_test_rri_format_hrp_abba_deadbeef(char *hrp,
                                                   const size_t hrp_len,
                                                   char *expected_rri) {
    base_test_rri_format_hrp("abbadeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
                             hrp,
                             hrp_len,
                             expected_rri);
}

static void test_rri_format_hrp_6_chars(void **state) {
    (void) state;

    char hrp[] = "stella";
    base_test_rri_format_hrp_abba_deadbeef(
        hrp,
        strlen(hrp),
        "stella_tr1qw4m4h4dhmhaatd7al02m0h0m6kmam774klwlh4dhmhsynma8s");
}

static void test_rri_format_hrp_7_chars(void **state) {
    (void) state;

    char hrp[] = "marantz";
    base_test_rri_format_hrp_abba_deadbeef(
        hrp,
        strlen(hrp),
        "marantz_tr1qw4m4h4dhmhaatd7al02m0h0m6kmam774klwlh4dhmhsavvmh6");
}

static void test_rri_format_hrp_8_chars(void **state) {
    (void) state;

    char hrp[] = "nintendo";
    base_test_rri_format_hrp_abba_deadbeef(
        hrp,
        strlen(hrp),
        "nintendo_tr1qw4m4h4dhmhaatd7al02m0h0m6kmam774klwlh4dhmhs65q8fx");
}

static void test_rri_format_hrp_9_chars(void **state) {
    (void) state;

    char hrp[] = "deadlocks";
    base_test_rri_format_hrp_abba_deadbeef(
        hrp,
        strlen(hrp),
        "deadlocks_tr1qw4m4h4dhmhaatd7al02m0h0m6kmam774klwlh4dhmhsfthmmw");
}

static void test_rri_format_hrp_10_chars(void **state) {
    (void) state;

    char hrp[] = "cryptocarp";
    base_test_rri_format_hrp_abba_deadbeef(
        hrp,
        strlen(hrp),
        "cryptocarp_tr1qw4m4h4dhmhaatd7al02m0h0m6kmam774klwlh4dhmhsn863zs");
}

static void test_rri_format_hrp_11_chars(void **state) {
    (void) state;

    char hrp[] = "frostbitten";
    base_test_rri_format_hrp_abba_deadbeef(
        hrp,
        strlen(hrp),
        "frostbitten_tr1qw4m4h4dhmhaatd7al02m0h0m6kmam774klwlh4dhmhsu6d2h5");
}

static void test_rri_format_hrp_12_chars(void **state) {
    (void) state;

    char hrp[] = "jeopordizing";
    base_test_rri_format_hrp_abba_deadbeef(
        hrp,
        strlen(hrp),
        "jeopordizing_tr1qw4m4h4dhmhaatd7al02m0h0m6kmam774klwlh4dhmhsunvd09");
}

static void test_rri_format_hrp_13_chars(void **state) {
    (void) state;

    char hrp[] = "paradoxically";
    base_test_rri_format_hrp_abba_deadbeef(
        hrp,
        strlen(hrp),
        "paradoxically_tr1qw4m4h4dhmhaatd7al02m0h0m6kmam774klwlh4dhmhsdxt0l3");
}

static void test_rri_format_hrp_14_chars(void **state) {
    (void) state;

    char hrp[] = "transformation";
    base_test_rri_format_hrp_abba_deadbeef(
        hrp,
        strlen(hrp),
        "transformation_tr1qw4m4h4dhmhaatd7al02m0h0m6kmam774klwlh4dhmhsc87hdp");
}

static void test_rri_format_hrp_15_chars(void **state) {
    (void) state;

    char hrp[] = "insignificantly";
    base_test_rri_format_hrp_abba_deadbeef(
        hrp,
        strlen(hrp),
        "insignificantly_tr1qw4m4h4dhmhaatd7al02m0h0m6kmam774klwlh4dhmhsw8cqlq");
}

static void test_rri_format_hrp_16_chars(void **state) {
    (void) state;

    char hrp[] = "characterisation";
    base_test_rri_format_hrp_abba_deadbeef(
        hrp,
        strlen(hrp),
        "characterisation_tr1qw4m4h4dhmhaatd7al02m0h0m6kmam774klwlh4dhmhs5fc4nz");
}

/**
 * @brief Test of successful parsing of TX
 */
static void test_success_token_transfer_only_xrd(void **state) {
    (void) state;

    expected_instruction_t expected_instructions[] = {
        {
            .ins_hex = "0d0001",
            .instruction_type = INS_HEADER,
            .substate_type = IRRELEVANT,
        },
        {
            .ins_hex = "07a0686a487f9d3adf4892a358e4460cda432068f069e5e9f4c815af21bc3dd1d600000000",
            .instruction_type = INS_DOWN,
            .substate_type = IRRELEVANT,
        },
        {
            .ins_hex = "01002100000000000000000000000000000000000000000000000abbade0b6b3a7640000",
            .instruction_type = INS_SYSCALL,
            .substate_type = IRRELEVANT,
        },
        {
            .ins_hex = "02000006000402935deebcad35bcf27d05b431276be8fcba26312cd1d54c33ac6748a72fe42"
                       "7ca0100000000000000000000000000000000000000000000d3c1e44bf21f03700000",
            .instruction_type = INS_UP,
            .substate_type = SUBSTATE_TYPE_TOKENS,
        },
        {
            .ins_hex = "00",
            .instruction_type = INS_END,
            .substate_type = IRRELEVANT,
        },
        {
            .ins_hex = "080000",
            .instruction_type = INS_LDOWN,
            .substate_type = IRRELEVANT,
        },
        {
            .ins_hex = "02000006000402935deebcad35bcf27d05b431276be8fcba26312cd1d54c33ac6748a72fe42"
                       "7ca0100000000000000000000000000000000000000000000d38bae82445924d00000",
            .instruction_type = INS_UP,
            .substate_type = SUBSTATE_TYPE_TOKENS,
        },
        {
            .ins_hex = "0200000600040356959464545aa2787984fe4ac76496721a22f150c0076724ad7190fe3a597"
                       "bb70100000000000000000000000000000000000000000000003635c9adc5dea00000",
            .instruction_type = INS_UP,
            .substate_type = SUBSTATE_TYPE_TOKENS,
        },
        {
            .ins_hex = "00",
            .instruction_type = INS_END,
            .substate_type = IRRELEVANT,
        },
        {
            .ins_hex = "010021010000000000000000000000000000000000000000000000000de0b6b3a7640000",
            .instruction_type = INS_SYSCALL,
            .substate_type = IRRELEVANT,
        },
        {
            .ins_hex = "02000006000402935deebcad35bcf27d05b431276be8fcba26312cd1d54c33ac6748a72fe42"
                       "7ca010000000000000000000000000000000000000000000000000de0b6b3a7640000",
            .instruction_type = INS_UP,
            .substate_type = SUBSTATE_TYPE_TOKENS,
        },
        {
            .ins_hex = "00",
            .instruction_type = INS_END,
            .substate_type = IRRELEVANT,
        }};

    test_vector_t test_vector = (test_vector_t){
        .total_number_of_instructions = 12,
        .expected_instructions = expected_instructions,
        .expected_result = EXPECTED_RESULT_SUCCESS,
        .expected_success = {
            .my_public_key_hex =
                "0356959464545aa2787984fe4ac76496721a22f150c0076724ad7190fe3a597bb7",
            .expected_tx_fee = "50684.735185526206758912",
            .expected_total_xrd_amount = "2049677.735185526206758912",
            .expected_hash =
                {
                    0x0b, 0xc5, 0x21, 0xbd, 0x59, 0x54, 0xb6, 0x6a, 0x1a, 0x0c, 0x7c,
                    0xe1, 0x01, 0x3a, 0xd6, 0x7c, 0xe2, 0x8e, 0x37, 0x9b, 0xe1, 0xc4,
                    0xf0, 0x33, 0x6d, 0xd9, 0xc6, 0x83, 0x58, 0x89, 0xb2, 0x31,
                },
        }};

    do_test_parse_tx(test_vector);
}

/**
 * @brief Test of successful parsing of TX
 */
static void test_success_token_transfer_only_xrd_with_msg(void **state) {
    (void) state;

    expected_instruction_t expected_instructions[] = {
        {
            .ins_hex = "0d0001",
            .instruction_type = INS_HEADER,
            .substate_type = IRRELEVANT,
        },
        {
            .ins_hex = "07973b739777f86d706b1ff85aaab35065e8de03da0fe83bbedf30a0acc0ec4ea500000001",
            .instruction_type = INS_DOWN,
            .substate_type = IRRELEVANT,
        },
        {
            .ins_hex = "01002100000000000000000000000000000000000000000000000deadde0b6b3a7640000",
            .instruction_type = INS_SYSCALL,
            .substate_type = IRRELEVANT,
        },
        {
            .ins_hex = "02000006000402935deebcad35bcf27d05b431276be8fcba26312cd1d54c33ac6748a72fe42"
                       "7ca0100000000000000000000000000000000000000000000d38ba0a18da57d6c0000",
            .instruction_type = INS_UP,
            .substate_type = SUBSTATE_TYPE_TOKENS,
        },
        {
            .ins_hex = "00",
            .instruction_type = INS_END,
            .substate_type = IRRELEVANT,
        },
        {
            .ins_hex = "080000",
            .instruction_type = INS_LDOWN,
            .substate_type = IRRELEVANT,
        },
        {
            .ins_hex = "02000006000402935deebcad35bcf27d05b431276be8fcba26312cd1d54c33ac6748a72fe42"
                       "7ca0100000000000000000000000000000000000000000000d38b5b3dfc2338780000",
            .instruction_type = INS_UP,
            .substate_type = SUBSTATE_TYPE_TOKENS,
        },
        {
            .ins_hex = "0200000600040356959464545aa2787984fe4ac76496721a22f150c0076724ad7190fe3a597"
                       "bb7010000000000000000000000000000000000000000000000004563918244f40000",
            .instruction_type = INS_UP,
            .substate_type = SUBSTATE_TYPE_TOKENS,
        },
        {
            .ins_hex = "00",
            .instruction_type = INS_END,
            .substate_type = IRRELEVANT,
        },
        {
            .ins_hex = "010021010000000000000000000000000000000000000000000000000de0b6b3a7640000",
            .instruction_type = INS_SYSCALL,
            .substate_type = IRRELEVANT,
        },
        {
            .ins_hex = "02000006000402935deebcad35bcf27d05b431276be8fcba26312cd1d54c33ac6748a72fe42"
                       "7ca010000000000000000000000000000000000000000000000000de0b6b3a7640000",
            .instruction_type = INS_UP,
            .substate_type = SUBSTATE_TYPE_TOKENS,
        },
        {
            .ins_hex = "00",
            .instruction_type = INS_END,
            .substate_type = IRRELEVANT,
        },
        {
            .ins_hex = "0c000548656c6c6f",
            .instruction_type = INS_MSG,
            .substate_type = IRRELEVANT,
        }};

    test_vector_t test_vector = (test_vector_t){
        .total_number_of_instructions = 13,
        .expected_instructions = expected_instructions,
        .expected_result = EXPECTED_RESULT_SUCCESS,
        .expected_success = {
            .my_public_key_hex =
                "0356959464545aa2787984fe4ac76496721a22f150c0076724ad7190fe3a597bb7",
            .expected_tx_fee = "65722.29037011331186688",
            .expected_total_xrd_amount = "2063708.29037011331186688",
            .expected_hash =
                {
                    0x39, 0x72, 0x63, 0xba, 0x56, 0xb6, 0xe6, 0x94, 0x16, 0x30, 0x49,
                    0x0b, 0x88, 0x83, 0x81, 0x45, 0xb7, 0xc1, 0x08, 0xfc, 0xcb, 0x24,
                    0x41, 0xee, 0x2d, 0xdd, 0xae, 0x01, 0xe8, 0xa4, 0x26, 0x82,
                },
        }};

    do_test_parse_tx(test_vector);
}

/**
 * @brief Test of successful parsing of TX
 */
static void test_success_token_transfer_xrd_and_non_xrd_mixed(void **state) {
    (void) state;

    expected_instruction_t expected_instructions[] = {
        {
            .ins_hex = "0d0001",
            .instruction_type = INS_HEADER,
            .substate_type = IRRELEVANT,
        },
        {
            .ins_hex = "076ae6ca1c740d4b7d1a9d07ddad52ca62226851ac9f595e390a6e5ab3bf4f626b00000003",
            .instruction_type = INS_DOWN,
            .substate_type = IRRELEVANT,
        },
        {
            .ins_hex = "01002100000000000000000000000000000000000000000000000abbade0b6b3a7640000",
            .instruction_type = INS_SYSCALL,
            .substate_type = IRRELEVANT,
        },
        {
            .ins_hex = "00",
            .instruction_type = INS_END,
            .substate_type = IRRELEVANT,
        },
        {
            .ins_hex = "07973b739777f86d706b1ff85aaab35065e8de03da0fe83bbedf30a0acc0ec4ea500000003",
            .instruction_type = INS_DOWN,
            .substate_type = IRRELEVANT,
        },
        {
            .ins_hex = "07a0686a487f9d3adf4892a358e4460cda432068f069e5e9f4c815af21bc3dd1d600000003",
            .instruction_type = INS_DOWN,
            .substate_type = IRRELEVANT,
        },
        {
            .ins_hex = "07b1f4197b20e6c64bee1f751b76a779293481c910f413c0fcafc0b993e10b137100000000",
            .instruction_type = INS_DOWN,
            .substate_type = IRRELEVANT,
        },
        {
            .ins_hex = "02000006000402935deebcad35bcf27d05b431276be8fcba26312cd1d54c33ac6748a72fe42"
                       "7ca0100000000000000000000000000000000000000000000d37ff8e81cc3e8700000",
            .instruction_type = INS_UP,
            .substate_type = SUBSTATE_TYPE_TOKENS,
        },
        {
            .ins_hex = "0200000600040356959464545aa2787984fe4ac76496721a22f150c0076724ad7190fe3a597"
                       "bb7010000000000000000000000000000000000000000000000004563918244f40000",
            .instruction_type = INS_UP,
            .substate_type = SUBSTATE_TYPE_TOKENS,
        },
        {
            .ins_hex = "00",
            .instruction_type = INS_END,
            .substate_type = IRRELEVANT,
        },
        {
            .ins_hex = "07c809308c578cbb2dc9e38ad49f9ac6b15826be4870bd5995e4e1872c3f0abe2a00000000",
            .instruction_type = INS_DOWN,
            .substate_type = IRRELEVANT,
        },
        {
            .ins_hex = "02000006000402935deebcad35bcf27d05b431276be8fcba26312cd1d54c33ac6748a72fe42"
                       "7ca039aee5d3daebf6b132c0c58b241f25f198ddcac69421759cb1c92000000000000000000"
                       "0000000000000000000000000000000000000000000005",
            .instruction_type = INS_UP,
            .substate_type = SUBSTATE_TYPE_TOKENS,
        },
        {
            .ins_hex = "0200000600040356959464545aa2787984fe4ac76496721a22f150c0076724ad7190fe3a597"
                       "bb7039aee5d3daebf6b132c0c58b241f25f198ddcac69421759cb1c92000000000000000000"
                       "0000000000000000000000000000000000000000000002",
            .instruction_type = INS_UP,
            .substate_type = SUBSTATE_TYPE_TOKENS,
        },
        {
            .ins_hex = "00",
            .instruction_type = INS_END,
            .substate_type = IRRELEVANT,
        },
        {
            .ins_hex = "010021010000000000000000000000000000000000000000000000000de0b6b3a7640000",
            .instruction_type = INS_SYSCALL,
            .substate_type = IRRELEVANT,
        },
        {
            .ins_hex = "02000006000402935deebcad35bcf27d05b431276be8fcba26312cd1d54c33ac6748a72fe42"
                       "7ca010000000000000000000000000000000000000000000000000de0b6b3a7640000",
            .instruction_type = INS_UP,
            .substate_type = SUBSTATE_TYPE_TOKENS,
        },
        {
            .ins_hex = "00",
            .instruction_type = INS_END,
            .substate_type = IRRELEVANT,
        }};

    test_vector_t test_vector = (test_vector_t){
        .total_number_of_instructions = 17,
        .expected_instructions = expected_instructions,
        .expected_result = EXPECTED_RESULT_SUCCESS,
        .expected_success = {
            .my_public_key_hex =
                "0356959464545aa2787984fe4ac76496721a22f150c0076724ad7190fe3a597bb7",
            .expected_tx_fee = "50684.735185526206758912",
            .expected_total_xrd_amount = "1049465.735185526206758912",
            .expected_hash =
                {
                    0x97, 0x1e, 0xaa, 0x2a, 0x95, 0x93, 0x9c, 0x37, 0x99, 0x9f, 0xc0,
                    0x70, 0x5c, 0x53, 0x5f, 0x20, 0xa4, 0x9a, 0x88, 0xea, 0xb5, 0x39,
                    0xed, 0xed, 0x82, 0xac, 0x4e, 0x8c, 0x13, 0xbc, 0xe2, 0xbf,
                },
        }};

    do_test_parse_tx(test_vector);
}

/**
 * @brief Test of successful parsing of TX
 */
static void test_success_xrd_transfer_to_self(void **state) {
    (void) state;

    expected_instruction_t expected_instructions[] = {
        {
            .ins_hex = "0d0001",
            .instruction_type = INS_HEADER,
            .substate_type = IRRELEVANT,
        },
        {
            .ins_hex = "070c7e6ad291944d3fdf50cd278651e4d20ad28536b529004008a4c3938dce092c00000003",
            .instruction_type = INS_DOWN,
            .substate_type = IRRELEVANT,
        },
        {
            .ins_hex = "01002100000000000000000000000000000000000000000000000abbade0b6b3a7640000",
            .instruction_type = INS_SYSCALL,
            .substate_type = IRRELEVANT,
        },
        {
            .ins_hex = "00",
            .instruction_type = INS_END,
            .substate_type = IRRELEVANT,
        },
        {
            .ins_hex = "076ae6ca1c740d4b7d1a9d07ddad52ca62226851ac9f595e390a6e5ab3bf4f626b00000000",
            .instruction_type = INS_DOWN,
            .substate_type = IRRELEVANT,
        },
        {
            .ins_hex = "02000006000402935deebcad35bcf27d05b431276be8fcba26312cd1d54c33ac6748a72fe42"
                       "7ca0100000000000000000000000000000000000000000000d380228a40dede9c0000",
            .instruction_type = INS_UP,
            .substate_type = SUBSTATE_TYPE_TOKENS,
        },
        {
            .ins_hex = "02000006000402935deebcad35bcf27d05b431276be8fcba26312cd1d54c33ac6748a72fe42"
                       "7ca010000000000000000000000000000000000000000000000004563918244f40000",
            .instruction_type = INS_UP,
            .substate_type = SUBSTATE_TYPE_TOKENS,
        },
        {
            .ins_hex = "00",
            .instruction_type = INS_END,
            .substate_type = IRRELEVANT,
        },
        {
            .ins_hex = "010021010000000000000000000000000000000000000000000000000de0b6b3a7640000",
            .instruction_type = INS_SYSCALL,
            .substate_type = IRRELEVANT,
        },
        {
            .ins_hex = "02000006000402935deebcad35bcf27d05b431276be8fcba26312cd1d54c33ac6748a72fe42"
                       "7ca010000000000000000000000000000000000000000000000000de0b6b3a7640000",
            .instruction_type = INS_UP,
            .substate_type = SUBSTATE_TYPE_TOKENS,
        },
        {
            .ins_hex = "00",
            .instruction_type = INS_END,
            .substate_type = IRRELEVANT,
        }};

    test_vector_t test_vector = (test_vector_t){
        .total_number_of_instructions = 11,
        .expected_instructions = expected_instructions,
        .expected_result = EXPECTED_RESULT_SUCCESS,
        .expected_success = {
            .my_public_key_hex =
                "02935deebcad35bcf27d05b431276be8fcba26312cd1d54c33ac6748a72fe427ca",
            .expected_tx_fee = "50684.735185526206758912",
            .expected_total_xrd_amount = "50684.735185526206758912",
            .expected_hash =
                {
                    0xa9, 0x56, 0xe6, 0xf6, 0xb4, 0x8f, 0xfb, 0xfc, 0xb8, 0xd6, 0x29,
                    0x37, 0x4c, 0x56, 0x1c, 0x71, 0xcf, 0x91, 0xa0, 0x64, 0x45, 0xa1,
                    0xda, 0x1c, 0x06, 0x8c, 0xcf, 0xb4, 0xbf, 0x12, 0x4d, 0x31,
                },
        }};

    do_test_parse_tx(test_vector);
}

/**
 * @brief Test of successful parsing of TX
 */
static void test_success_token_transfer_and_stake(void **state) {
    (void) state;

    expected_instruction_t expected_instructions[] = {
        {
            .ins_hex = "0d0001",
            .instruction_type = INS_HEADER,
            .substate_type = IRRELEVANT,
        },
        {
            .ins_hex = "076a950e22681f3db30ab6fd4714815443fb680249ea07d65adee004a46a80daac00000000",
            .instruction_type = INS_DOWN,
            .substate_type = IRRELEVANT,
        },
        {
            .ins_hex = "01002100000000000000000000000000000000000000000000000000017efb8762c98000",
            .instruction_type = INS_SYSCALL,
            .substate_type = IRRELEVANT,
        },
        {
            .ins_hex = "0200450600040385be69c03154ba40a0a3ea8d06d31e256b1bdb4f6753543db88d2b173f4b5"
                       "dfd01000000000000000000000000000000000000000000000036326a5e8f76348000",
            .instruction_type = INS_UP,
            .substate_type = SUBSTATE_TYPE_TOKENS,
        },
        {
            .ins_hex = "00",
            .instruction_type = INS_END,
            .substate_type = IRRELEVANT,
        },
        {
            .ins_hex = "080000",
            .instruction_type = INS_LDOWN,
            .substate_type = IRRELEVANT,
        },
        {
            .ins_hex = "0200450600040385be69c03154ba40a0a3ea8d06d31e256b1bdb4f6753543db88d2b173f4b5"
                       "dfd0100000000000000000000000000000000000000000000002b5adba234b0148000",
            .instruction_type = INS_UP,
            .substate_type = SUBSTATE_TYPE_TOKENS,
        },
        {
            .ins_hex = "05004529f251379200c559e01b8e3fb7b4c7cf9bf23279dc6ebd26ba20a5f4e88c772e00000"
                       "0050385be69c03154ba40a0a3ea8d06d31e256b1bdb4f6753543db88d2b173f4b5dfd",
            .instruction_type = INS_VREAD,
            .substate_type = IRRELEVANT,
        },
        {
            .ins_hex = "05004529f251379200c559e01b8e3fb7b4c7cf9bf23279dc6ebd26ba20a5f4e88c772e00000"
                       "0080385be69c03154ba40a0a3ea8d06d31e256b1bdb4f6753543db88d2b173f4b5dfd",
            .instruction_type = INS_VREAD,
            .substate_type = IRRELEVANT,
        },
        {
            .ins_hex = "02006507000385be69c03154ba40a0a3ea8d06d31e256b1bdb4f6753543db88d2b173f4b5df"
                       "d040385be69c03154ba40a0a3ea8d06d31e256b1bdb4f6753543db88d2b173f4b5dfd000000"
                       "00000000000000000000000000000000000000000ad78ebc5ac6200000",
            .instruction_type = INS_UP,
            .substate_type = SUBSTATE_TYPE_PREPARED_STAKE,
        },
        {
            .ins_hex = "00",
            .instruction_type = INS_END,
            .substate_type = IRRELEVANT,
        }};

    test_vector_t test_vector = (test_vector_t){
        .total_number_of_instructions = 11,
        .expected_instructions = expected_instructions,
        .expected_result = EXPECTED_RESULT_SUCCESS,
        .expected_success = {
            .my_public_key_hex =
                "0356959464545aa2787984fe4ac76496721a22f150c0076724ad7190fe3a597bb7",
            .expected_tx_fee = "0.1078",
            .expected_total_xrd_amount = "1799.6218",
            .expected_hash =
                {
                    0xb6, 0x6d, 0x4f, 0x03, 0x7e, 0xf0, 0x33, 0x4d, 0x5c, 0xf0, 0xfa,
                    0x10, 0x80, 0x58, 0xcc, 0x27, 0x36, 0x9b, 0x69, 0x56, 0x6b, 0x9c,
                    0xc7, 0x9b, 0x76, 0x46, 0x37, 0xc5, 0x79, 0xaa, 0x37, 0x95,
                },
        }};

    do_test_parse_tx(test_vector);
}

uint8_t test_vector_0[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,}; // 0
uint8_t test_vector_1[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,}; // 1
uint8_t test_vector_2[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0c,}; // 12
uint8_t test_vector_3[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x7b,}; // 123
uint8_t test_vector_4[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x3b, 0x9a, 0xca, 0x00,}; // 1000000000
uint8_t test_vector_5[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xcb, 0x41, 0x78, 0x00,}; // 12000000000
uint8_t test_vector_6[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x1c, 0xa3, 0x5f, 0x0e, 0x00,}; // 123000000000
uint8_t test_vector_7[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xe8, 0xd4, 0xa5, 0x10, 0x00,}; // 1000000000000
uint8_t test_vector_8[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0a, 0xe9, 0xf7, 0xbc, 0xc0, 0x00,}; // 12000000000000
uint8_t test_vector_9[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x6f, 0xde, 0x2b, 0x4e, 0xb0, 0x00,}; // 123000000000000
uint8_t test_vector_10[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x8d, 0x7e, 0xa4, 0xc6, 0x80, 0x00,}; // 1000000000000000
uint8_t test_vector_11[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x2a, 0xa1, 0xef, 0xb9, 0x4e, 0x00, 0x00,}; // 12000000000000000
uint8_t test_vector_12[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xb4, 0xfb, 0xd9, 0x2b, 0x5f, 0x80, 0x00,}; // 123000000000000000
uint8_t test_vector_13[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0d, 0xe0, 0xb6, 0xb3, 0xa7, 0x64, 0x00, 0x00,}; // 1000000000000000000
uint8_t test_vector_14[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xa6, 0x88, 0x90, 0x6b, 0xd8, 0xb0, 0x00, 0x00,}; // 12000000000000000000
uint8_t test_vector_15[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0xaa, 0xf7, 0xc8, 0x51, 0x6d, 0x0c, 0x00, 0x00,}; // 123000000000000000000
uint8_t test_vector_16[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0d, 0xe0, 0xb6, 0xb3, 0xa7, 0x64, 0x00, 0x01,}; // 1000000000000000001
uint8_t test_vector_17[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0d, 0xe0, 0xb6, 0xb3, 0xa7, 0x64, 0x00, 0x0c,}; // 1000000000000000012
uint8_t test_vector_18[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0d, 0xe0, 0xb6, 0xb3, 0xa7, 0x64, 0x00, 0x7b,}; // 1000000000000000123
uint8_t test_vector_19[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0d, 0xe0, 0xb6, 0xb3, 0xa7, 0x64, 0x04, 0xd2,}; // 1000000000000001234
uint8_t test_vector_20[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0d, 0xe0, 0xb6, 0xb3, 0xa7, 0x64, 0x30, 0x39,}; // 1000000000000012345
uint8_t test_vector_21[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0d, 0xe0, 0xb6, 0xb3, 0xa7, 0x65, 0xe2, 0x40,}; // 1000000000000123456
uint8_t test_vector_22[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0d, 0xe0, 0xb6, 0xb3, 0xa7, 0x76, 0xd6, 0x87,}; // 1000000000001234567
uint8_t test_vector_23[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0d, 0xe0, 0xb6, 0xb3, 0xa8, 0x20, 0x61, 0x4e,}; // 1000000000012345678
uint8_t test_vector_24[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0d, 0xe0, 0xb6, 0xb3, 0xae, 0xbf, 0xcd, 0x15,}; // 1000000000123456789
uint8_t test_vector_25[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0d, 0xe0, 0xb6, 0xb3, 0xea, 0x5a, 0x97, 0x15,}; // 1000000001123456789
uint8_t test_vector_26[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0d, 0xe0, 0xb6, 0xb6, 0x7a, 0x01, 0x45, 0x15,}; // 1000000012123456789
uint8_t test_vector_27[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0d, 0xe0, 0xb6, 0xd0, 0x52, 0x1e, 0xdb, 0x15,}; // 1000000123123456789
uint8_t test_vector_28[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0d, 0xe0, 0xb7, 0xd2, 0xfe, 0xe1, 0x81, 0x15,}; // 1000001234123456789
uint8_t test_vector_29[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0d, 0xe0, 0xc1, 0xed, 0xfa, 0x16, 0xc7, 0x15,}; // 1000012345123456789
uint8_t test_vector_30[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0d, 0xe1, 0x26, 0xfc, 0x05, 0xc6, 0x4d, 0x15,}; // 1000123456123456789
uint8_t test_vector_31[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0d, 0xe5, 0x19, 0x88, 0xb6, 0x3c, 0x53, 0x15,}; // 1001234567123456789
uint8_t test_vector_32[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0e, 0x0c, 0x93, 0x07, 0xd6, 0x73, 0x59, 0x15,}; // 1012345678123456789
uint8_t test_vector_33[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0f, 0x97, 0x51, 0xff, 0x54, 0x34, 0x5f, 0x15,}; // 1123456789123456789
uint8_t test_vector_34[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xa6, 0x88, 0x90, 0x6b, 0xd8, 0xb0, 0x00, 0x01,}; // 12000000000000000001
uint8_t test_vector_35[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xa6, 0x88, 0x90, 0x6b, 0xd8, 0xb0, 0x00, 0x0c,}; // 12000000000000000012
uint8_t test_vector_36[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xa6, 0x88, 0x90, 0x6b, 0xd8, 0xb0, 0x00, 0x7b,}; // 12000000000000000123
uint8_t test_vector_37[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xa6, 0x88, 0x90, 0x6b, 0xd8, 0xb0, 0x04, 0xd2,}; // 12000000000000001234
uint8_t test_vector_38[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xa6, 0x88, 0x90, 0x6b, 0xd8, 0xb0, 0x30, 0x39,}; // 12000000000000012345
uint8_t test_vector_39[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xa6, 0x88, 0x90, 0x6b, 0xd8, 0xb1, 0xe2, 0x40,}; // 12000000000000123456
uint8_t test_vector_40[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xa6, 0x88, 0x90, 0x6b, 0xd8, 0xc2, 0xd6, 0x87,}; // 12000000000001234567
uint8_t test_vector_41[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xa6, 0x88, 0x90, 0x6b, 0xd9, 0x6c, 0x61, 0x4e,}; // 12000000000012345678
uint8_t test_vector_42[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xa6, 0x88, 0x90, 0x6b, 0xe0, 0x0b, 0xcd, 0x15,}; // 12000000000123456789
uint8_t test_vector_43[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xa6, 0x88, 0x90, 0x6c, 0x1b, 0xa6, 0x97, 0x15,}; // 12000000001123456789
uint8_t test_vector_44[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xa6, 0x88, 0x90, 0x6e, 0xab, 0x4d, 0x45, 0x15,}; // 12000000012123456789
uint8_t test_vector_45[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xa6, 0x88, 0x90, 0x88, 0x83, 0x6a, 0xdb, 0x15,}; // 12000000123123456789
uint8_t test_vector_46[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xa6, 0x88, 0x91, 0x8b, 0x30, 0x2d, 0x81, 0x15,}; // 12000001234123456789
uint8_t test_vector_47[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xa6, 0x88, 0x9b, 0xa6, 0x2b, 0x62, 0xc7, 0x15,}; // 12000012345123456789
uint8_t test_vector_48[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xa6, 0x89, 0x00, 0xb4, 0x37, 0x12, 0x4d, 0x15,}; // 12000123456123456789
uint8_t test_vector_49[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xa6, 0x8c, 0xf3, 0x40, 0xe7, 0x88, 0x53, 0x15,}; // 12001234567123456789
uint8_t test_vector_50[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xa6, 0xb4, 0x6c, 0xc0, 0x07, 0xbf, 0x59, 0x15,}; // 12012345678123456789
uint8_t test_vector_51[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xa8, 0x3f, 0x2b, 0xb7, 0x85, 0x80, 0x5f, 0x15,}; // 12123456789123456789

static void test_single_format_vector(uint8_t* amount_input, char* expected) {
    char formatted[128] = {0};
    uint256_t amount = {0};

    readu256BE(amount_input, &amount);

    assert_true(to_string_uint256(&amount, formatted, sizeof(formatted)));
    assert_string_equal(expected, formatted);
}

static void test_format_tokens(void** state) {
    (void) state;

    test_single_format_vector(test_vector_0, "0");
    test_single_format_vector(test_vector_1, "0.000000000000000001");
    test_single_format_vector(test_vector_2, "0.000000000000000012");
    test_single_format_vector(test_vector_3, "0.000000000000000123");
    test_single_format_vector(test_vector_4, "0.000000001");
    test_single_format_vector(test_vector_5, "0.000000012");
    test_single_format_vector(test_vector_6, "0.000000123");
    test_single_format_vector(test_vector_7, "0.000001");
    test_single_format_vector(test_vector_8, "0.000012");
    test_single_format_vector(test_vector_9, "0.000123");
    test_single_format_vector(test_vector_10, "0.001");
    test_single_format_vector(test_vector_11, "0.012");
    test_single_format_vector(test_vector_12, "0.123");
    test_single_format_vector(test_vector_13, "1");
    test_single_format_vector(test_vector_14, "12");
    test_single_format_vector(test_vector_15, "123");
    test_single_format_vector(test_vector_16, "1.000000000000000001");
    test_single_format_vector(test_vector_17, "1.000000000000000012");
    test_single_format_vector(test_vector_18, "1.000000000000000123");
    test_single_format_vector(test_vector_19, "1.000000000000001234");
    test_single_format_vector(test_vector_20, "1.000000000000012345");
    test_single_format_vector(test_vector_21, "1.000000000000123456");
    test_single_format_vector(test_vector_22, "1.000000000001234567");
    test_single_format_vector(test_vector_23, "1.000000000012345678");
    test_single_format_vector(test_vector_24, "1.000000000123456789");
    test_single_format_vector(test_vector_25, "1.000000001123456789");
    test_single_format_vector(test_vector_26, "1.000000012123456789");
    test_single_format_vector(test_vector_27, "1.000000123123456789");
    test_single_format_vector(test_vector_28, "1.000001234123456789");
    test_single_format_vector(test_vector_29, "1.000012345123456789");
    test_single_format_vector(test_vector_30, "1.000123456123456789");
    test_single_format_vector(test_vector_31, "1.001234567123456789");
    test_single_format_vector(test_vector_32, "1.012345678123456789");
    test_single_format_vector(test_vector_33, "1.123456789123456789");
    test_single_format_vector(test_vector_34, "12.000000000000000001");
    test_single_format_vector(test_vector_35, "12.000000000000000012");
    test_single_format_vector(test_vector_36, "12.000000000000000123");
    test_single_format_vector(test_vector_37, "12.000000000000001234");
    test_single_format_vector(test_vector_38, "12.000000000000012345");
    test_single_format_vector(test_vector_39, "12.000000000000123456");
    test_single_format_vector(test_vector_40, "12.000000000001234567");
    test_single_format_vector(test_vector_41, "12.000000000012345678");
    test_single_format_vector(test_vector_42, "12.000000000123456789");
    test_single_format_vector(test_vector_43, "12.000000001123456789");
    test_single_format_vector(test_vector_44, "12.000000012123456789");
    test_single_format_vector(test_vector_45, "12.000000123123456789");
    test_single_format_vector(test_vector_46, "12.000001234123456789");
    test_single_format_vector(test_vector_47, "12.000012345123456789");
    test_single_format_vector(test_vector_48, "12.000123456123456789");
    test_single_format_vector(test_vector_49, "12.001234567123456789");
    test_single_format_vector(test_vector_50, "12.012345678123456789");
    test_single_format_vector(test_vector_51, "12.123456789123456789");
}

int main() {
    const struct CMUnitTest rri_formatting[] = {
        cmocka_unit_test(test_rri_format_hrp_6_chars),
        cmocka_unit_test(test_rri_format_hrp_7_chars),
        cmocka_unit_test(test_rri_format_hrp_8_chars),
        cmocka_unit_test(test_rri_format_hrp_9_chars),
        cmocka_unit_test(test_rri_format_hrp_10_chars),
        cmocka_unit_test(test_rri_format_hrp_11_chars),
        cmocka_unit_test(test_rri_format_hrp_12_chars),
        cmocka_unit_test(test_rri_format_hrp_13_chars),
        cmocka_unit_test(test_rri_format_hrp_14_chars),
        cmocka_unit_test(test_rri_format_hrp_15_chars),
        cmocka_unit_test(test_rri_format_hrp_16_chars),
    };

    const struct CMUnitTest success_complex_tx[] = {
        cmocka_unit_test(test_success_token_transfer_and_stake),
        cmocka_unit_test(test_success_token_transfer_only_xrd),
        cmocka_unit_test(test_success_token_transfer_only_xrd_with_msg),
        cmocka_unit_test(test_success_token_transfer_xrd_and_non_xrd_mixed),
        cmocka_unit_test(test_success_xrd_transfer_to_self),
    };

    const struct CMUnitTest failing_txs[] = {
        cmocka_unit_test(test_failure_missing_header),
        cmocka_unit_test(test_failure_invalid_header_invalid_version),
        cmocka_unit_test(test_failure_invalid_header_invalid_flag),
        cmocka_unit_test(test_failure_no_fee_in_tx),
        cmocka_unit_test(test_failure_invalid_syscall_too_few_bytes),
        cmocka_unit_test(test_failure_claiming_tx_is_larger_than_sum_of_instruction_byte_count),
        cmocka_unit_test(test_failure_claiming_tx_is_smaller_than_sum_of_instruction_byte_count),
        cmocka_unit_test(test_failure_extra_bytes_after_instruction),

        // Unsupported/Invalid Instructions
        cmocka_unit_test(test_failure_unrecognized_instruction),
        cmocka_unit_test(test_failure_unsupported_instruction_lread_0x04),
        cmocka_unit_test(test_failure_unsupported_instruction_lvread_0x06),
        cmocka_unit_test(test_failure_unsupported_instruction_vdown_0x09),
        cmocka_unit_test(test_failure_unsupported_instruction_lvdown_0x0a),
        cmocka_unit_test(test_failure_unsupported_instruction_readindex_0x0e),
        cmocka_unit_test(test_failure_unsupported_instruction_downindex_0x0f),

        // Unsupported/Invalid Substate Types
        cmocka_unit_test(test_failure_unrecognized_substate_type),
        cmocka_unit_test(test_failure_unsupported_substate_type_0x00),
        cmocka_unit_test(test_failure_unsupported_substate_type_0x01),
        cmocka_unit_test(test_failure_unsupported_substate_type_0x02),
        cmocka_unit_test(test_failure_unsupported_substate_type_0x03),
        cmocka_unit_test(test_failure_unsupported_substate_type_0x04),
        cmocka_unit_test(test_failure_unsupported_substate_type_0x05),
        cmocka_unit_test(test_failure_unsupported_substate_type_0x0a),
        cmocka_unit_test(test_failure_unsupported_substate_type_0x0b),
        cmocka_unit_test(test_failure_unsupported_substate_type_0x0c),
        cmocka_unit_test(test_failure_unsupported_substate_type_0x0d),
        cmocka_unit_test(test_failure_unsupported_substate_type_0x0f),
        cmocka_unit_test(test_failure_unsupported_substate_type_0x10),

        // Failed to parse tokens
        // Invalid Owner
        cmocka_unit_test(test_failure_parse_tokens_invalid_owner_address_type_0x01_system),
        cmocka_unit_test(test_failure_parse_tokens_invalid_owner_address_type_0x03_hashed_pubkey),
        cmocka_unit_test(test_failure_parse_tokens_invalid_owner_too_few_bytes),

        // Invalid RRI
        cmocka_unit_test(test_failure_parse_tokens_invalid_resource_unrecognized_address_type_0xff),
        cmocka_unit_test(
            test_failure_parse_tokens_invalid_resource_usupported_address_type_system_0x00),
        cmocka_unit_test(test_failure_parse_tokens_invalid_resource_hashed_key_too_short),
        cmocka_unit_test(test_failure_parse_tokens_invalid_resource_incompatible_address_type),

    };

    const struct CMUnitTest formatting_tests[] = {
        cmocka_unit_test(test_format_tokens),
    };

    int status = 0;

    status += cmocka_run_group_tests_name("RRI", rri_formatting, NULL, NULL);
    status += cmocka_run_group_tests_name("Valid transactions", success_complex_tx, NULL, NULL);
    status += cmocka_run_group_tests_name("Invalid transactions", failing_txs, NULL, NULL);
    status += cmocka_run_group_tests_name("Amount formatting", formatting_tests, NULL, NULL);
    return status;
}
