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
#include "common/format.h"

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
    size_t ins_len;
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

static void dbg_print_expected_result(expected_result_e expected_result) {
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

static void dbg_print_test_vector(test_vector_t *test_vector) {
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
    expected_instruction_t *expected_instructions = test_vector.expected_instructions;

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
    if (expected_failure &&
        test_vector.expected_failure.contains_misleading_tx_size_used_to_trigger_failure) {
        tx_byte_count = test_vector.expected_failure.misleading_tx_size_used_to_trigger_failure;
    } else {
        for (i = 0; i < total_number_of_instructions; i++) {
            expected_instruction_t *expected_instruction = &expected_instructions[i];
            size_t instruction_size = expected_instruction->ins_len;
            tx_byte_count += instruction_size;
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

    expected_instruction_t expected_instruction;
    parse_and_process_instruction_outcome_t outcome;
    bool parse_instruction_successful = false;
    re_instruction_type_e parsed_ins_type;

    for (i = 0; i < total_number_of_instructions; i++) {
        bool is_last_instruction = i == total_number_of_instructions - 1;
        expected_instruction = expected_instructions[i];
        size_t instruction_size = expected_instruction.ins_len;
        buf.offset = 0;
        buf.size = instruction_size;
        memset(bytes255, 0, sizeof(bytes255));
        hex_to_bin(expected_instruction.ins_hex, bytes255, instruction_size);
        buf.ptr = bytes255;

        // print_message("Printing bufer\n");
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

        if (expected_failure && expect_to_fail_at_this_specific_instruction) {
            // Should not have succeded to parse or process since we expecte failure.
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

                assert_int_equal(parsed_ins_type, expected_instruction.instruction_type);
                if (parsed_ins_type == INS_UP) {
                    re_substate_type_e parsed_substate_type =
                        tx_parser.instruction_parser.instruction.ins_up.substate.type;
                    assert_int_equal(parsed_substate_type, expected_instruction.substate_type);
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
            .ins_len = 37,
            .ins_hex = "044b95e6aa95cae5010419b986e8913a5c9628647b0ea21d977dc96c4baa4ef2d200000001",
            .instruction_type = INS_DOWN,
            .substate_type = IRRELEVANT,
        },
        {
            .ins_len = 35,
            .ins_hex = "092100000000000000000000000000000000000000000000000000000000000000fade",
            .instruction_type = INS_SYSCALL,
            .substate_type = IRRELEVANT,
        },
        {
            .ins_len = 69,
            .ins_hex = "01030104034ca24c2b7000f439ca21cbb11b044d48f90c987b2aee6608a2570a466612dae20"
                       "000000000000000000000000000000000000000000000008ac7230489e7fffc",
            .instruction_type = INS_UP,
            .substate_type = SUBSTATE_TYPE_TOKENS,
        },
        {
            .ins_len = 1,
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
            .ins_len = 3,
            .ins_hex = "0aff01",  // invalid version byte 0xff instead of valid 0x00 (second
                                  // byte, "flag" byte is valid though)
            .instruction_type = INS_HEADER,
            .substate_type = IRRELEVANT,
        },
        {
            .ins_len = 1,
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
            .ins_len = 3,
            .ins_hex = "0a0002",  // invalid "flag" byte: 0x02 instead of valid 0x01 ("version"
                                  // byte is valid though.)
            .instruction_type = INS_HEADER,
            .substate_type = IRRELEVANT,
        },
        {
            .ins_len = 1,
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
            .index_of_failing_instruction = 0,
            .expected_failure_outcome = {
                .outcome_type = PARSE_PROCESS_INS_FAILED_TO_PARSE,
                .parse_failure = {
                    .outcome_type = PARSE_INS_INVALID_HEADER,
                }
            }
        }
    };
    // clang-format on

    do_test_parse_tx(test_vector);
}

static void test_failure_no_fee_in_tx(void **state) {
    (void) state;

    // This tx lacks the SYSCALL instruction, containing the tx fee.
    expected_instruction_t expected_instructions[] = {
        {
            .ins_len = 3,
            .ins_hex = "0a0001",
            .instruction_type = INS_HEADER,
            .substate_type = IRRELEVANT,
        },
        {
            .ins_len = 69,
            .ins_hex = "01030104034ca24c2b7000f439ca21cbb11b044d48f90c987b2aee6608a2570a466612dae20"
                       "000000000000000000000000000000000000000000000008ac7230489e7fffc",
            .instruction_type = INS_UP,
            .substate_type = SUBSTATE_TYPE_TOKENS,
        },
        {
            .ins_len = 1,
            .ins_hex = "00",
            .instruction_type = INS_END,
            .substate_type = IRRELEVANT,
        },
    };

    uint16_t total_number_of_instructions = 3;
    // clang-format off
    test_vector_t test_vector = (test_vector_t){
        .total_number_of_instructions = total_number_of_instructions,
        .expected_instructions = expected_instructions,
        .expected_result = EXPECTED_FAILURE_REASON_SPECIFIC_INSTRUCTION,
        .expected_failure = {
            .expected_failure_outcome = {
                .outcome_type = PARSE_PROCESS_INS_TX_DOES_NOT_CONTAIN_TX_FEE,
            },
            .index_of_failing_instruction = total_number_of_instructions - 1, // will not fail until last INS has been parsed.
        }
    };
    // clang-format on

    do_test_parse_tx(test_vector);
}

static void test_failure_invalid_syscall_too_few_bytes(void **state) {
    (void) state;

    // This tx contains an invalid SYSCALL instruction => fail to parse tx fee
    expected_instruction_t expected_instructions[] = {
        {
            .ins_len = 3,
            .ins_hex = "0a0001",
            .instruction_type = INS_HEADER,
            .substate_type = IRRELEVANT,
        },
        {
            .ins_len = 37,
            .ins_hex = "044b95e6aa95cae5010419b986e8913a5c9628647b0ea21d977dc96c4baa4ef2d20"
                       "0000001",
            .instruction_type = INS_DOWN,
            .substate_type = IRRELEVANT,
        },
        {
            .ins_len = 35,
            .ins_hex = "0901000000000000000000000000000000000000000000000000000000000000000"
                       "007",  // invalid, expected 0x0921, where `0x09` denotes `SYSCALL`
                               // and `0x21`, being hex for 0d33, telling us SYSCALL
                               // contains of 33 bytes, instead this hex specifies 0x01.
            .instruction_type = INS_SYSCALL,
            .substate_type = IRRELEVANT,
        },
        {
            .ins_len = 69,
            .ins_hex = "01030104034ca24c2b7000f439ca21cbb11b044d48f90c987b2aee6608a2570a466"
                       "612dae20"
                       "000000000000000000000000000000000000000000000008ac7230489e7fffc",
            .instruction_type = INS_UP,
            .substate_type = SUBSTATE_TYPE_TOKENS,
        },
        {
            .ins_len = 1,
            .ins_hex = "00",
            .instruction_type = INS_END,
            .substate_type = IRRELEVANT,
        },
    };

    // clang-format off
    test_vector_t test_vector = (test_vector_t){
        .total_number_of_instructions = 5,
        .expected_instructions = expected_instructions,
        .expected_result = EXPECTED_FAILURE_REASON_SPECIFIC_INSTRUCTION,
        .expected_failure = {
            .index_of_failing_instruction = 2, 
            .expected_failure_outcome = {
                .outcome_type = PARSE_PROCESS_INS_PARSE_TX_FEE_FROM_SYSCALL_FAIL,
            }
        }
    };
    // clang-format on

    do_test_parse_tx(test_vector);
}

static void test_failure_claiming_tx_is_larger_than_sum_of_instruction_byte_count(void **state) {
    (void) state;

    expected_instruction_t expected_instructions[] = {
        {
            .ins_len = 3,
            .ins_hex = "0a0001",
            .instruction_type = INS_HEADER,
            .substate_type = IRRELEVANT,
        },
        {
            .ins_len = 35,
            .ins_hex = "092100000000000000000000000000000000000000000000000000000000000000fade",
            .instruction_type = INS_SYSCALL,
            .substate_type = IRRELEVANT,
        },
        {
            .ins_len = 1,
            .ins_hex = "00",
            .instruction_type = INS_END,
            .substate_type = IRRELEVANT,
        },
    };

    uint16_t total_number_of_instructions = 3;
    // clang-format off
    test_vector_t test_vector = (test_vector_t){
        .total_number_of_instructions = total_number_of_instructions,
        .expected_instructions = expected_instructions,
        .expected_result = EXPECTED_FAILURE_REASON_SPECIFIC_INSTRUCTION,
        .expected_failure = {
            .contains_misleading_tx_size_used_to_trigger_failure = true,
            .misleading_tx_size_used_to_trigger_failure = 123456789, // we mislead here, actual size is 39 bytes.
            .index_of_failing_instruction = total_number_of_instructions - 1, // fail at last
            .expected_failure_outcome = {
                .outcome_type = PARSE_PROCESS_INS_BYTE_COUNT_MISMATCH,
            }
        }
    };
    // clang-format on

    do_test_parse_tx(test_vector);
}

static void test_failure_claiming_tx_is_smaller_than_sum_of_instruction_byte_count(void **state) {
    (void) state;

    expected_instruction_t expected_instructions[] = {
        {
            .ins_len = 3,
            .ins_hex = "0a0001",
            .instruction_type = INS_HEADER,
            .substate_type = IRRELEVANT,
        },
        {
            .ins_len = 35,
            .ins_hex = "092100000000000000000000000000000000000000000000000000000000000000fade",
            .instruction_type = INS_SYSCALL,
            .substate_type = IRRELEVANT,
        },
        {
            .ins_len = 1,
            .ins_hex = "00",
            .instruction_type = INS_END,
            .substate_type = IRRELEVANT,
        },
    };

    // clang-format off
    test_vector_t test_vector = (test_vector_t){
        .total_number_of_instructions = 3,
        .expected_instructions = expected_instructions,
        .expected_result = EXPECTED_FAILURE_REASON_SPECIFIC_INSTRUCTION,
        .expected_failure = {
            .contains_misleading_tx_size_used_to_trigger_failure = true,
            .misleading_tx_size_used_to_trigger_failure = 5, // we mislead here, actual size is 39 bytes.
            .index_of_failing_instruction = 1, // fail at second, because already after second we have parsed too many bytes.
            .expected_failure_outcome = {
                .outcome_type = PARSE_PROCESS_INS_BYTE_COUNT_MISMATCH,
            }
        }
    };
    // clang-format on

    do_test_parse_tx(test_vector);
}

static void test_failure_unrecognized_instruction(void **state) {
    (void) state;

    expected_instruction_t expected_instructions[] = {
        {
            .ins_len = 3,
            .ins_hex = "0a0001",
            .instruction_type = INS_HEADER,
            .substate_type = IRRELEVANT,
        },
        {
            .ins_len = 37,
            .ins_hex = "044b95e6aa95cae5010419b986e8913a5c9628647b0ea21d977dc96c4baa4ef2d20"
                       "0000001",
            .instruction_type = INS_DOWN,
            .substate_type = IRRELEVANT,
        },
        {
            .ins_len = 35,
            .ins_hex = "092100000000000000000000000000000000000000000000000000000000000000fade",
            .instruction_type = INS_SYSCALL,
            .substate_type = IRRELEVANT,
        },
        {
            .ins_len = 1,
            .ins_hex = "ff",
            .instruction_type = 0xff,
            .substate_type = IRRELEVANT,
        },
        {
            .ins_len = 1,
            .ins_hex = "00",
            .instruction_type = INS_END,
            .substate_type = IRRELEVANT,
        },
    };

    // clang-format off
    test_vector_t test_vector = (test_vector_t){
        .total_number_of_instructions = 5,
        .expected_instructions = expected_instructions,
        .expected_result = EXPECTED_FAILURE_REASON_SPECIFIC_INSTRUCTION,
        .expected_failure = {
            .index_of_failing_instruction = 3, 
            .expected_failure_outcome = {
                .outcome_type = PARSE_PROCESS_INS_FAILED_TO_PARSE,
                .parse_failure = {
                    .outcome_type = PARSE_INS_FAIL_UNREGOZNIED_INSTRUCTION_TYPE,
                    .unrecognized_instruction_type_value =  0xff,
                }
            }
        }
    };
    // clang-format on

    do_test_parse_tx(test_vector);
}

static void test_failure_unsupported_instruction(char *unsupported_as_hex) {
    uint8_t unsupported_instruction;
    hex_to_bin(unsupported_as_hex, &unsupported_instruction, 1);

    expected_instruction_t expected_instructions[] = {
        {
            .ins_len = 3,
            .ins_hex = "0a0001",
            .instruction_type = INS_HEADER,
            .substate_type = IRRELEVANT,
        },
        {
            .ins_len = 37,
            .ins_hex = "044b95e6aa95cae5010419b986e8913a5c9628647b0ea21d977dc96c4baa4ef2d20"
                       "0000001",
            .instruction_type = INS_DOWN,
            .substate_type = IRRELEVANT,
        },
        {
            .ins_len = 35,
            .ins_hex = "092100000000000000000000000000000000000000000000000000000000000000fade",
            .instruction_type = INS_SYSCALL,
            .substate_type = IRRELEVANT,
        },
        {
            .ins_len = 1,
            .ins_hex = unsupported_as_hex,
            .instruction_type = unsupported_instruction,
            .substate_type = IRRELEVANT,
        },
        {
            .ins_len = 1,
            .ins_hex = "00",
            .instruction_type = INS_END,
            .substate_type = IRRELEVANT,
        },
    };

    // clang-format off
    test_vector_t test_vector = (test_vector_t){
        .total_number_of_instructions = 5,
        .expected_instructions = expected_instructions,
        .expected_result = EXPECTED_FAILURE_REASON_SPECIFIC_INSTRUCTION,
        .expected_failure = {
            .index_of_failing_instruction = 3, 
            .expected_failure_outcome = {
                .outcome_type = PARSE_PROCESS_INS_FAILED_TO_PARSE,
                .parse_failure = {
                    .outcome_type = PARSE_INS_FAIL_UNSUPPORTED_INSTRUCTION_TYPE,
                    .unsupported_instruction_type_value = unsupported_instruction,
                }
            }
        }
    };
    // clang-format on

    do_test_parse_tx(test_vector);
}

static void test_failure_unsupported_instruction_vdown_0x02(void **state) {
    (void) state;
    test_failure_unsupported_instruction("02");
}

static void test_failure_unsupported_instruction_vdownarg_0x03(void **state) {
    (void) state;
    test_failure_unsupported_instruction("03");
}

static void test_failure_unsupported_instruction_sig_0x07(void **state) {
    (void) state;
    test_failure_unsupported_instruction("07");
}

static void test_failure_unsupported_instruction_downall_0x08(void **state) {
    (void) state;
    test_failure_unsupported_instruction("08");
}

static void test_failure_unrecognized_substate_type(void **state) {
    (void) state;

    expected_instruction_t expected_instructions[] = {
        {
            .ins_len = 3,
            .ins_hex = "0a0001",
            .instruction_type = INS_HEADER,
            .substate_type = IRRELEVANT,
        },
        {
            .ins_len = 37,
            .ins_hex = "044b95e6aa95cae5010419b986e8913a5c9628647b0ea21d977dc96c4baa4ef2d20"
                       "0000001",
            .instruction_type = INS_DOWN,
            .substate_type = IRRELEVANT,
        },
        {
            .ins_len = 35,
            .ins_hex = "092100000000000000000000000000000000000000000000000000000000000000fade",
            .instruction_type = INS_SYSCALL,
            .substate_type = IRRELEVANT,
        },
        {
            .ins_len = 2,
            .ins_hex = "01ff",  // 0x01 is INS_UP, and 0xff is an unrecognized substate type
            .instruction_type = INS_UP,
            .substate_type = 0xff,  // Unrecognized
        },
        {
            .ins_len = 1,
            .ins_hex = "00",
            .instruction_type = INS_END,
            .substate_type = IRRELEVANT,
        },
    };

    // clang-format off
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
                    .substate_failure =  {
                        .outcome_type = PARSE_SUBSTATE_FAIL_UNRECOGNIZED_SUBSTATE_TYPE,
                        .unrecognized_substate_type_value = 0xff,
                    },
                }
            }
        }
    };
    // clang-format on

    do_test_parse_tx(test_vector);
}

static void test_failure_unsupported_substate_type(char *unsupported_ins_as_hex) {
    uint8_t unsupported_substate;
    hex_to_bin(unsupported_ins_as_hex + 2, &unsupported_substate, 1);

    expected_instruction_t expected_instructions[] = {
        {
            .ins_len = 3,
            .ins_hex = "0a0001",
            .instruction_type = INS_HEADER,
            .substate_type = IRRELEVANT,
        },
        {
            .ins_len = 37,
            .ins_hex = "044b95e6aa95cae5010419b986e8913a5c9628647b0ea21d977dc96c4baa4ef2d200000001",
            .instruction_type = INS_DOWN,
            .substate_type = IRRELEVANT,
        },
        {
            .ins_len = 35,
            .ins_hex = "092100000000000000000000000000000000000000000000000000000000000000fade",
            .instruction_type = INS_SYSCALL,
            .substate_type = IRRELEVANT,
        },
        {
            .ins_len = 2,
            .ins_hex = unsupported_ins_as_hex,
            .instruction_type = INS_UP,
            .substate_type = unsupported_substate,
        },
        {
            .ins_len = 1,
            .ins_hex = "00",
            .instruction_type = INS_END,
            .substate_type = IRRELEVANT,
        },
    };

    // clang-format off
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
                    .substate_failure =  {
                        .outcome_type = PARSE_SUBSTATE_FAIL_UNSUPPORTED_SUBSTATE_TYPE,
                        .unsupported_substate_type_value = unsupported_substate,
                    },
                }
            }
        }
    };
    // clang-format on

    do_test_parse_tx(test_vector);
}

static void test_failure_unsupported_substate_type_re_address_0x00(void **state) {
    (void) state;
    test_failure_unsupported_substate_type(
        "0100");  // 01 for INS_UP, 00 for substate type RE_ADDRESS.
}

static void test_failure_unsupported_substate_type_token_definition_0x02(void **state) {
    (void) state;
    test_failure_unsupported_substate_type(
        "0102");  // 01 for INS_UP, 02 for substate type TOKEN_DEFINITION.
}

static void test_failure_unsupported_substate_type_validator_0x05(void **state) {
    (void) state;
    test_failure_unsupported_substate_type(
        "0105");  // 01 for INS_UP, 05 for substate type VALIDATOR.
}

static void test_failure_unsupported_substate_type_unique_0x06(void **state) {
    (void) state;
    test_failure_unsupported_substate_type("0106");  // 01 for INS_UP, 06 for substate type UNIQUE.
}

static void test_failure_unsupported_substate_type_exiting_stake_0x0e(void **state) {
    (void) state;
    test_failure_unsupported_substate_type(
        "010e");  // 01 for INS_UP, 0e for substate type EXITING STAKE.
}

static void base_test_failure_parse_token(parse_tokens_outcome_t tokens_failure,
                                          char *ins_hex_invalid_up_tokens,
                                          size_t ins_hex_invalid_up_tokens_len) {
    expected_instruction_t expected_instructions[] = {
        {
            .ins_len = 3,
            .ins_hex = "0a0001",
            .instruction_type = INS_HEADER,
            .substate_type = IRRELEVANT,
        },
        {
            .ins_len = 37,
            .ins_hex = "04c1e268b8b61ce5688d039aefa1e5ea6612a6c4d3b497713582916b533d6c502800000003",
            .instruction_type = INS_DOWN,
            .substate_type = IRRELEVANT,
        },
        {
            .ins_len = 35,
            .ins_hex = "0921000000000000000000000000000000000000000000000038821089088b6063da18",
            .instruction_type = INS_SYSCALL,
            .substate_type = IRRELEVANT,
        },
        {
            .ins_len = ins_hex_invalid_up_tokens_len,
            .ins_hex = ins_hex_invalid_up_tokens,
            .instruction_type = INS_UP,
            .substate_type = SUBSTATE_TYPE_TOKENS,
        },
        {
            .ins_len = 1,
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

static void base_test_failure_parse_tokens_invalid_rri(
    parse_address_failure_reason_e underlying_rri_failure,
    char *ins_hex_invalid_up_tokens,
    size_t ins_hex_invalid_up_tokens_len) {
    base_test_failure_parse_token(
        (parse_tokens_outcome_t){
            .outcome_type = PARSE_TOKENS_FAILURE_PARSE_RESOURCE,
            .resource_parse_failure_reason = underlying_rri_failure,
        },
        ins_hex_invalid_up_tokens,
        ins_hex_invalid_up_tokens_len);
}

static void test_failure_parse_tokens_invalid_rri_unrecognized_address_type_0xff(void **state) {
    (void) state;
    // 01=INS_UP, 03=TOKENS, ff=first byte of Tokens, being Address, specifying an unrecognized
    // Address Type value of 0xff
    base_test_failure_parse_tokens_invalid_rri(PARSE_ADDRESS_FAIL_UNRECOGNIZED_ADDRESS_TYPE,
                                               "0103ff",
                                               3);
}

static void test_failure_parse_tokens_invalid_rri_usupported_address_type_system_0x00(
    void **state) {
    (void) state;
    // 01=INS_UP, 03=TOKENS, 00=first byte of Tokens, being Address, specifying an unsupported
    // Address Type value of 0x00 (RE_ADDRESS_SYSTEM).
    base_test_failure_parse_tokens_invalid_rri(PARSE_ADDRESS_FAIL_UNSUPPORTED_ADDRESS_TYPE,
                                               "010300",
                                               3);
}

static void test_failure_parse_tokens_invalid_rri_hashed_key_too_short(void **state) {
    (void) state;
    // 01=INS_UP, 03=TOKENS, 03=first byte of Tokens, being Address, specifying an HashedKeyNonce
    // and `0xff` being just one byte instead of expected 26 bytes => too short.
    base_test_failure_parse_tokens_invalid_rri(PARSE_ADDRESS_FAIL_HASHEDKEY_NOT_ENOUGH_BYTES,
                                               "010303ff",
                                               4);
}

static void test_failure_parse_tokens_invalid_rri_incompatible_address_type(void **state) {
    (void) state;
    // 01=INS_UP, 03=TOKENS, 04=first byte of Tokens, being Address, specifying an PublicKey, which
    // is incompatible with RRI.
    base_test_failure_parse_tokens_invalid_rri(
        PARSED_ADDRESS_FAIL_EXPECTED_TYPE_COMPATIBLE_WITH_RESOURCE,
        "0103040345497f80cf2c495286a146178bc2ad1a95232a8fce45856c55d67716cda020b9",
        36);
}

static void base_test_failure_parse_tokens_invalid_owner(
    parse_address_failure_reason_e underlying_owner_failure,
    char *ins_hex_invalid_up_tokens,
    size_t ins_hex_invalid_up_tokens_len) {
    base_test_failure_parse_token(
        (parse_tokens_outcome_t){
            .outcome_type = PARSE_TOKENS_FAILURE_PARSE_OWNER,
            .owner_parse_failure_reason = underlying_owner_failure,
        },
        ins_hex_invalid_up_tokens,
        ins_hex_invalid_up_tokens_len);
}

static void test_failure_parse_tokens_invalid_owner_address_type_0x01_system(void **state) {
    (void) state;
    base_test_failure_parse_tokens_invalid_owner(
        PARSED_ADDRESS_FAIL_EXPECTED_TYPE_COMPATIBLE_ACCOUNT_OR_VALIDATOR_ADDRESS,
        "010301"  // valid start of tokens:  01=INS_UP, 03=TOKENS, 01=RE_ADDRESS_SYSTEM (valid RRI)
        "01",  // specifying RE_ADDRESS_SYSTEM (used for RRI), which is invalid for account address
        4);
}

static void test_failure_parse_tokens_invalid_owner_address_type_0x03_hashed_pubkey(void **state) {
    (void) state;
    base_test_failure_parse_tokens_invalid_owner(
        PARSED_ADDRESS_FAIL_EXPECTED_TYPE_COMPATIBLE_ACCOUNT_OR_VALIDATOR_ADDRESS,
        "010301"  // valid start of tokens:  01=INS_UP, 03=TOKENS, 01=RE_ADDRESS_SYSTEM (valid RRI)
        "03ababdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",  // specifying
                                                                   // RE_ADDRESS_HASHED_KEY_NONCE
                                                                   // (used for RRI), which is
                                                                   // invalid for account address
        30);
}

static void test_failure_parse_tokens_invalid_owner_too_few_bytes(void **state) {
    (void) state;
    base_test_failure_parse_tokens_invalid_owner(
        PARSE_ADDRESS_FAIL_PUBKEY_NOT_ENOUGH_BYTES,
        "010301"  // valid start of tokens:  01=INS_UP, 03=TOKENS, 01=RE_ADDRESS_SYSTEM (valid RRI)
        "04ff",   // valid type, but too few bytes
        5);
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
        "stella_rb1qw4m4h4dhmhaatd7al02m0h0m6kmam774klwlh4dhmhsa766sk");
}

static void test_rri_format_hrp_7_chars(void **state) {
    (void) state;

    char hrp[] = "marantz";
    base_test_rri_format_hrp_abba_deadbeef(
        hrp,
        strlen(hrp),
        "marantz_rb1qw4m4h4dhmhaatd7al02m0h0m6kmam774klwlh4dhmhsypduqu");
}

static void test_rri_format_hrp_8_chars(void **state) {
    (void) state;

    char hrp[] = "nintendo";
    base_test_rri_format_hrp_abba_deadbeef(
        hrp,
        strlen(hrp),
        "nintendo_rb1qw4m4h4dhmhaatd7al02m0h0m6kmam774klwlh4dhmhsrepq7q");
}

static void test_rri_format_hrp_9_chars(void **state) {
    (void) state;

    char hrp[] = "deadlocks";
    base_test_rri_format_hrp_abba_deadbeef(
        hrp,
        strlen(hrp),
        "deadlocks_rb1qw4m4h4dhmhaatd7al02m0h0m6kmam774klwlh4dhmhssxkuvg");
}

static void test_rri_format_hrp_10_chars(void **state) {
    (void) state;

    char hrp[] = "cryptocarp";
    base_test_rri_format_hrp_abba_deadbeef(
        hrp,
        strlen(hrp),
        "cryptocarp_rb1qw4m4h4dhmhaatd7al02m0h0m6kmam774klwlh4dhmhs22mk4k");
}

static void test_rri_format_hrp_11_chars(void **state) {
    (void) state;

    char hrp[] = "frostbitten";
    base_test_rri_format_hrp_abba_deadbeef(
        hrp,
        strlen(hrp),
        "frostbitten_rb1qw4m4h4dhmhaatd7al02m0h0m6kmam774klwlh4dhmhs9hvdqj");
}

static void test_rri_format_hrp_12_chars(void **state) {
    (void) state;

    char hrp[] = "jeopordizing";
    base_test_rri_format_hrp_abba_deadbeef(
        hrp,
        strlen(hrp),
        "jeopordizing_rb1qw4m4h4dhmhaatd7al02m0h0m6kmam774klwlh4dhmhs97d2cr");
}

static void test_rri_format_hrp_13_chars(void **state) {
    (void) state;

    char hrp[] = "paradoxically";
    base_test_rri_format_hrp_abba_deadbeef(
        hrp,
        strlen(hrp),
        "paradoxically_rb1qw4m4h4dhmhaatd7al02m0h0m6kmam774klwlh4dhmhs5t2ggh");
}

static void test_rri_format_hrp_14_chars(void **state) {
    (void) state;

    char hrp[] = "transformation";
    base_test_rri_format_hrp_abba_deadbeef(
        hrp,
        strlen(hrp),
        "transformation_rb1qw4m4h4dhmhaatd7al02m0h0m6kmam774klwlh4dhmhsp2ls68");
}

static void test_rri_format_hrp_15_chars(void **state) {
    (void) state;

    char hrp[] = "insignificantly";
    base_test_rri_format_hrp_abba_deadbeef(
        hrp,
        strlen(hrp),
        "insignificantly_rb1qw4m4h4dhmhaatd7al02m0h0m6kmam774klwlh4dhmhsh2e8gx");
}

static void test_rri_format_hrp_16_chars(void **state) {
    (void) state;

    char hrp[] = "characterisation";
    base_test_rri_format_hrp_abba_deadbeef(
        hrp,
        strlen(hrp),
        "characterisation_rb1qw4m4h4dhmhaatd7al02m0h0m6kmam774klwlh4dhmhsdyejyy");
}

/**
 * @brief Test of successful parsing of TX with #398 bytes and #12 instructions..
 *
 * Test parsing transaction with blob:
 * 0a000104a0686a487f9d3adf4892a358e4460cda432068f069e5e9f4c815af21bc3dd1d600000000
  092100000000000000000000000000000000000000000000000abbade0b6b3a76400000105000402
  935deebcad35bcf27d05b431276be8fcba26312cd1d54c33ac6748a72fe427ca0100000000000000
  000000000000000000000000000000d3c1e44bf21f037000000005000000000105000402935deebc
  ad35bcf27d05b431276be8fcba26312cd1d54c33ac6748a72fe427ca010000000000000000000000
  0000000000000000000000d38bae82445924d00000010500040356959464545aa2787984fe4ac764
  96721a22f150c0076724ad7190fe3a597bb701000000000000000000000000000000000000000000
  00003635c9adc5dea00000000921010000000000000000000000000000000000000000000000000d
  e0b6b3a76400000105000402935deebcad35bcf27d05b431276be8fcba26312cd1d54c33ac6748a7
  2fe427ca010000000000000000000000000000000000000000000000000de0b6b3a764000000
 *
 * Deserializes into these instructions:
 * Instructions:
|- HEADER(0, 1)
|- DOWN(SubstateId { hash: 0xa0686a487f9d3adf4892a
  358e4460cda432068f069e5e9f4c815af21bc3dd1d6, index: 0 })
|- SYSCALL(0x0000000000
  0000000000000000000000000000000000000abbade0b6b3a7640000)
|- UP(Tokens { reserve
  d: 0, owner: 0x0402935deebcad35bcf27d05b431276be8fcba26312cd1d54c33ac6748a72fe42
  7ca, resource: 0x01, amount: U256 { raw: 999996000000000000000000 } })
|- END
|-
   LDOWN(0)
|- UP(Tokens { reserved: 0, owner: 0x0402935deebcad35bcf27d05b431276be
  8fcba26312cd1d54c33ac6748a72fe427ca, resource: 0x01, amount: U256 { raw: 9989960
  00000000000000000 } })
|- UP(Tokens { reserved: 0, owner: 0x040356959464545aa278
  7984fe4ac76496721a22f150c0076724ad7190fe3a597bb7, resource: 0x01, amount: U256 {
   raw: 1000000000000000000000 } })
|- END
|- SYSCALL(0x01000000000000000000000000
  0000000000000000000000000de0b6b3a7640000)
|- UP(Tokens { reserved: 0, owner: 0x0
  402935deebcad35bcf27d05b431276be8fcba26312cd1d54c33ac6748a72fe427ca, resource: 0
  x01, amount: U256 { raw: 1000000000000000000 } })
|- END
 *
 * Expected hash of transaction:
 * 2376fa3504b06ad5df0ddfc9baa67af328d1d55a6bbd75e32429b773f18eda6a
 *
 */
static void test_success_token_transfer_only_xrd(void **state) {
    (void) state;

    expected_instruction_t expected_instructions[] = {

        {
            .ins_len = 3,
            .ins_hex = "0a0001",
            .instruction_type = INS_HEADER,
            .substate_type = IRRELEVANT,
        },

        {
            .ins_len = 37,
            .ins_hex = "04a0686a487f9d3adf4892a358e4460cda432068f069e5e9f4c815af21bc3dd1d600000000",
            .instruction_type = INS_DOWN,
            .substate_type = IRRELEVANT,
        },

        {
            .ins_len = 35,
            .ins_hex = "092100000000000000000000000000000000000000000000000abbade0b6b3a7640000",
            .instruction_type = INS_SYSCALL,
            .substate_type = IRRELEVANT,
        },

        {
            .ins_len = 70,
            .ins_hex = "0105000402935deebcad35bcf27d05b431276be8fcba26312cd1d54c33ac6748a72fe427ca0"
                       "100000000000000000000000000000000000000000000d3c1e44bf21f03700000",
            .instruction_type = INS_UP,
            .substate_type = SUBSTATE_TYPE_TOKENS,
        },

        {
            .ins_len = 1,
            .ins_hex = "00",
            .instruction_type = INS_END,
            .substate_type = IRRELEVANT,
        },

        {
            .ins_len = 5,
            .ins_hex = "0500000000",
            .instruction_type = INS_LDOWN,
            .substate_type = IRRELEVANT,
        },

        {
            .ins_len = 70,
            .ins_hex = "0105000402935deebcad35bcf27d05b431276be8fcba26312cd1d54c33ac6748a72fe427ca0"
                       "100000000000000000000000000000000000000000000d38bae82445924d00000",
            .instruction_type = INS_UP,
            .substate_type = SUBSTATE_TYPE_TOKENS,
        },

        {
            .ins_len = 70,
            .ins_hex = "010500040356959464545aa2787984fe4ac76496721a22f150c0076724ad7190fe3a597bb70"
                       "100000000000000000000000000000000000000000000003635c9adc5dea00000",
            .instruction_type = INS_UP,
            .substate_type = SUBSTATE_TYPE_TOKENS,
        },

        {
            .ins_len = 1,
            .ins_hex = "00",
            .instruction_type = INS_END,
            .substate_type = IRRELEVANT,
        },

        {
            .ins_len = 35,
            .ins_hex = "0921010000000000000000000000000000000000000000000000000de0b6b3a7640000",
            .instruction_type = INS_SYSCALL,
            .substate_type = IRRELEVANT,
        },

        {
            .ins_len = 70,
            .ins_hex = "0105000402935deebcad35bcf27d05b431276be8fcba26312cd1d54c33ac6748a72fe427ca0"
                       "10000000000000000000000000000000000000000000000000de0b6b3a7640000",
            .instruction_type = INS_UP,
            .substate_type = SUBSTATE_TYPE_TOKENS,
        },

        {
            .ins_len = 1,
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
            .expected_tx_fee = "50684735185526206758912",
            .expected_total_xrd_amount = "2049677735185526206758912",
            .expected_hash =
                {// clang-format off
            0x23, 0x76, 0xfa, 0x35, 0x4, 0xb0, 0x6a, 0xd5,
            0xdf, 0xd, 0xdf, 0xc9, 0xba, 0xa6, 0x7a, 0xf3,
            0x28, 0xd1, 0xd5, 0x5a, 0x6b, 0xbd, 0x75, 0xe3,
            0x24, 0x29, 0xb7, 0x73, 0xf1, 0x8e, 0xda, 0x6a
                  },  // clang-format on
        }};

    do_test_parse_tx(test_vector);
}

/**
 * @brief Test of successful parsing of TX with #405 bytes and #13 instructions..
 *
 * Test parsing transaction with blob:
 * 0a000104973b739777f86d706b1ff85aaab35065e8de03da0fe83bbedf30a0acc0ec4ea500000001
  092100000000000000000000000000000000000000000000000deadde0b6b3a76400000105000402
  935deebcad35bcf27d05b431276be8fcba26312cd1d54c33ac6748a72fe427ca0100000000000000
  000000000000000000000000000000d38ba0a18da57d6c00000005000000000105000402935deebc
  ad35bcf27d05b431276be8fcba26312cd1d54c33ac6748a72fe427ca010000000000000000000000
  0000000000000000000000d38b5b3dfc2338780000010500040356959464545aa2787984fe4ac764
  96721a22f150c0076724ad7190fe3a597bb701000000000000000000000000000000000000000000
  0000004563918244f40000000921010000000000000000000000000000000000000000000000000d
  e0b6b3a76400000105000402935deebcad35bcf27d05b431276be8fcba26312cd1d54c33ac6748a7
  2fe427ca010000000000000000000000000000000000000000000000000de0b6b3a7640000000605
  48656c6c6f
 *
 * Deserializes into these instructions:
 * Instructions:
|- HEADER(0, 1)
|- DOWN(SubstateId { hash: 0x973b739777f86d706b1ff
  85aaab35065e8de03da0fe83bbedf30a0acc0ec4ea5, index: 1 })
|- SYSCALL(0x0000000000
  0000000000000000000000000000000000000deadde0b6b3a7640000)
|- UP(Tokens { reserve
  d: 0, owner: 0x0402935deebcad35bcf27d05b431276be8fcba26312cd1d54c33ac6748a72fe42
  7ca, resource: 0x01, amount: U256 { raw: 998995000000000000000000 } })
|- END
|-
   LDOWN(0)
|- UP(Tokens { reserved: 0, owner: 0x0402935deebcad35bcf27d05b431276be
  8fcba26312cd1d54c33ac6748a72fe427ca, resource: 0x01, amount: U256 { raw: 9989900
  00000000000000000 } })
|- UP(Tokens { reserved: 0, owner: 0x040356959464545aa278
  7984fe4ac76496721a22f150c0076724ad7190fe3a597bb7, resource: 0x01, amount: U256 {
   raw: 5000000000000000000 } })
|- END
|- SYSCALL(0x01000000000000000000000000000
  0000000000000000000000de0b6b3a7640000)
|- UP(Tokens { reserved: 0, owner: 0x0402
  935deebcad35bcf27d05b431276be8fcba26312cd1d54c33ac6748a72fe427ca, resource: 0x01
  , amount: U256 { raw: 1000000000000000000 } })
|- END
|- MSG(0x48656c6c6f)
 *
 * Expected hash of transaction:
 * c63d3cc2ea97a928eb7e3565bbac31c2f3f3406ee4d255cef186f37648c79b1c
 *
 */
static void test_success_token_transfer_only_xrd_with_msg(void **state) {
    (void) state;

    expected_instruction_t expected_instructions[] = {

        {
            .ins_len = 3,
            .ins_hex = "0a0001",
            .instruction_type = INS_HEADER,
            .substate_type = IRRELEVANT,
        },

        {
            .ins_len = 37,
            .ins_hex = "04973b739777f86d706b1ff85aaab35065e8de03da0fe83bbedf30a0acc0ec4ea500000001",
            .instruction_type = INS_DOWN,
            .substate_type = IRRELEVANT,
        },

        {
            .ins_len = 35,
            .ins_hex = "092100000000000000000000000000000000000000000000000deadde0b6b3a7640000",
            .instruction_type = INS_SYSCALL,
            .substate_type = IRRELEVANT,
        },

        {
            .ins_len = 70,
            .ins_hex = "0105000402935deebcad35bcf27d05b431276be8fcba26312cd1d54c33ac6748a72fe427ca0"
                       "100000000000000000000000000000000000000000000d38ba0a18da57d6c0000",
            .instruction_type = INS_UP,
            .substate_type = SUBSTATE_TYPE_TOKENS,
        },

        {
            .ins_len = 1,
            .ins_hex = "00",
            .instruction_type = INS_END,
            .substate_type = IRRELEVANT,
        },

        {
            .ins_len = 5,
            .ins_hex = "0500000000",
            .instruction_type = INS_LDOWN,
            .substate_type = IRRELEVANT,
        },

        {
            .ins_len = 70,
            .ins_hex = "0105000402935deebcad35bcf27d05b431276be8fcba26312cd1d54c33ac6748a72fe427ca0"
                       "100000000000000000000000000000000000000000000d38b5b3dfc2338780000",
            .instruction_type = INS_UP,
            .substate_type = SUBSTATE_TYPE_TOKENS,
        },

        {
            .ins_len = 70,
            .ins_hex = "010500040356959464545aa2787984fe4ac76496721a22f150c0076724ad7190fe3a597bb70"
                       "10000000000000000000000000000000000000000000000004563918244f40000",
            .instruction_type = INS_UP,
            .substate_type = SUBSTATE_TYPE_TOKENS,
        },

        {
            .ins_len = 1,
            .ins_hex = "00",
            .instruction_type = INS_END,
            .substate_type = IRRELEVANT,
        },

        {
            .ins_len = 35,
            .ins_hex = "0921010000000000000000000000000000000000000000000000000de0b6b3a7640000",
            .instruction_type = INS_SYSCALL,
            .substate_type = IRRELEVANT,
        },

        {
            .ins_len = 70,
            .ins_hex = "0105000402935deebcad35bcf27d05b431276be8fcba26312cd1d54c33ac6748a72fe427ca0"
                       "10000000000000000000000000000000000000000000000000de0b6b3a7640000",
            .instruction_type = INS_UP,
            .substate_type = SUBSTATE_TYPE_TOKENS,
        },

        {
            .ins_len = 1,
            .ins_hex = "00",
            .instruction_type = INS_END,
            .substate_type = IRRELEVANT,
        },

        {
            .ins_len = 7,
            .ins_hex = "060548656c6c6f",
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
            .expected_tx_fee = "65722290370113311866880",
            .expected_total_xrd_amount = "2063708290370113311866880",
            .expected_hash =
                {// clang-format off
            0xc6, 0x3d, 0x3c, 0xc2, 0xea, 0x97, 0xa9, 0x28,
            0xeb, 0x7e, 0x35, 0x65, 0xbb, 0xac, 0x31, 0xc2,
            0xf3, 0xf3, 0x40, 0x6e, 0xe4, 0xd2, 0x55, 0xce,
            0xf1, 0x86, 0xf3, 0x76, 0x48, 0xc7, 0x9b, 0x1c
                  },  // clang-format on
        }};

    do_test_parse_tx(test_vector);
}

/**
 * @brief Test of successful parsing of TX with #664 bytes and #17 instructions..
 *
 * Test parsing transaction with blob:
 * 0a0001046ae6ca1c740d4b7d1a9d07ddad52ca62226851ac9f595e390a6e5ab3bf4f626b00000003
  092100000000000000000000000000000000000000000000000abbade0b6b3a76400000004973b73
  9777f86d706b1ff85aaab35065e8de03da0fe83bbedf30a0acc0ec4ea50000000304a0686a487f9d
  3adf4892a358e4460cda432068f069e5e9f4c815af21bc3dd1d60000000304b1f4197b20e6c64bee
  1f751b76a779293481c910f413c0fcafc0b993e10b1371000000000105000402935deebcad35bcf2
  7d05b431276be8fcba26312cd1d54c33ac6748a72fe427ca01000000000000000000000000000000
  00000000000000d37ff8e81cc3e8700000010500040356959464545aa2787984fe4ac76496721a22
  f150c0076724ad7190fe3a597bb70100000000000000000000000000000000000000000000000045
  63918244f400000004c809308c578cbb2dc9e38ad49f9ac6b15826be4870bd5995e4e1872c3f0abe
  2a000000000105000402935deebcad35bcf27d05b431276be8fcba26312cd1d54c33ac6748a72fe4
  27ca039aee5d3daebf6b132c0c58b241f25f198ddcac69421759cb1c920000000000000000000000
  000000000000000000000000000000000000000005010500040356959464545aa2787984fe4ac764
  96721a22f150c0076724ad7190fe3a597bb7039aee5d3daebf6b132c0c58b241f25f198ddcac6942
  1759cb1c920000000000000000000000000000000000000000000000000000000000000002000921
  010000000000000000000000000000000000000000000000000de0b6b3a76400000105000402935d
  eebcad35bcf27d05b431276be8fcba26312cd1d54c33ac6748a72fe427ca01000000000000000000
  0000000000000000000000000000000de0b6b3a764000000
 *
 * Deserializes into these instructions:
 * Instructions:
|- HEADER(0, 1)
|- DOWN(SubstateId { hash: 0x6ae6ca1c740d4b7d1a9d0
  7ddad52ca62226851ac9f595e390a6e5ab3bf4f626b, index: 3 })
|- SYSCALL(0x0000000000
  0000000000000000000000000000000000000abbade0b6b3a7640000)
|- END
|- DOWN(Substat
  eId { hash: 0x973b739777f86d706b1ff85aaab35065e8de03da0fe83bbedf30a0acc0ec4ea5,
  index: 3 })
|- DOWN(SubstateId { hash: 0xa0686a487f9d3adf4892a358e4460cda432068f
  069e5e9f4c815af21bc3dd1d6, index: 3 })
|- DOWN(SubstateId { hash: 0xb1f4197b20e6
  c64bee1f751b76a779293481c910f413c0fcafc0b993e10b1371, index: 0 })
|- UP(Tokens {
   reserved: 0, owner: 0x0402935deebcad35bcf27d05b431276be8fcba26312cd1d54c33ac674
  8a72fe427ca, resource: 0x01, amount: U256 { raw: 998780000000000000000000 } })
|
  - UP(Tokens { reserved: 0, owner: 0x040356959464545aa2787984fe4ac76496721a22f150
  c0076724ad7190fe3a597bb7, resource: 0x01, amount: U256 { raw: 500000000000000000
  0 } })
|- END
|- DOWN(SubstateId { hash: 0xc809308c578cbb2dc9e38ad49f9ac6b15826b
  e4870bd5995e4e1872c3f0abe2a, index: 0 })
|- UP(Tokens { reserved: 0, owner: 0x04
  02935deebcad35bcf27d05b431276be8fcba26312cd1d54c33ac6748a72fe427ca, resource: 0x
  039aee5d3daebf6b132c0c58b241f25f198ddcac69421759cb1c92, amount: U256 { raw: 5 }
  })
|- UP(Tokens { reserved: 0, owner: 0x040356959464545aa2787984fe4ac76496721a22
  f150c0076724ad7190fe3a597bb7, resource: 0x039aee5d3daebf6b132c0c58b241f25f198ddc
  ac69421759cb1c92, amount: U256 { raw: 2 } })
|- END
|- SYSCALL(0x010000000000000
  000000000000000000000000000000000000de0b6b3a7640000)
|- UP(Tokens { reserved: 0,
   owner: 0x0402935deebcad35bcf27d05b431276be8fcba26312cd1d54c33ac6748a72fe427ca,
  resource: 0x01, amount: U256 { raw: 1000000000000000000 } })
|- END
 *
 * Expected hash of transaction:
 * 89d340c682104ea2932373f1ef51c30708b1121447602e50293a807962c93ef1
 *
 */
static void test_success_token_transfer_xrd_and_non_xrd_mixed(void **state) {
    (void) state;

    expected_instruction_t expected_instructions[] = {

        {
            .ins_len = 3,
            .ins_hex = "0a0001",
            .instruction_type = INS_HEADER,
            .substate_type = IRRELEVANT,
        },

        {
            .ins_len = 37,
            .ins_hex = "046ae6ca1c740d4b7d1a9d07ddad52ca62226851ac9f595e390a6e5ab3bf4f626b00000003",
            .instruction_type = INS_DOWN,
            .substate_type = IRRELEVANT,
        },

        {
            .ins_len = 35,
            .ins_hex = "092100000000000000000000000000000000000000000000000abbade0b6b3a7640000",
            .instruction_type = INS_SYSCALL,
            .substate_type = IRRELEVANT,
        },

        {
            .ins_len = 1,
            .ins_hex = "00",
            .instruction_type = INS_END,
            .substate_type = IRRELEVANT,
        },

        {
            .ins_len = 37,
            .ins_hex = "04973b739777f86d706b1ff85aaab35065e8de03da0fe83bbedf30a0acc0ec4ea500000003",
            .instruction_type = INS_DOWN,
            .substate_type = IRRELEVANT,
        },

        {
            .ins_len = 37,
            .ins_hex = "04a0686a487f9d3adf4892a358e4460cda432068f069e5e9f4c815af21bc3dd1d600000003",
            .instruction_type = INS_DOWN,
            .substate_type = IRRELEVANT,
        },

        {
            .ins_len = 37,
            .ins_hex = "04b1f4197b20e6c64bee1f751b76a779293481c910f413c0fcafc0b993e10b137100000000",
            .instruction_type = INS_DOWN,
            .substate_type = IRRELEVANT,
        },

        {
            .ins_len = 70,
            .ins_hex = "0105000402935deebcad35bcf27d05b431276be8fcba26312cd1d54c33ac6748a72fe427ca0"
                       "100000000000000000000000000000000000000000000d37ff8e81cc3e8700000",
            .instruction_type = INS_UP,
            .substate_type = SUBSTATE_TYPE_TOKENS,
        },

        {
            .ins_len = 70,
            .ins_hex = "010500040356959464545aa2787984fe4ac76496721a22f150c0076724ad7190fe3a597bb70"
                       "10000000000000000000000000000000000000000000000004563918244f40000",
            .instruction_type = INS_UP,
            .substate_type = SUBSTATE_TYPE_TOKENS,
        },

        {
            .ins_len = 1,
            .ins_hex = "00",
            .instruction_type = INS_END,
            .substate_type = IRRELEVANT,
        },

        {
            .ins_len = 37,
            .ins_hex = "04c809308c578cbb2dc9e38ad49f9ac6b15826be4870bd5995e4e1872c3f0abe2a00000000",
            .instruction_type = INS_DOWN,
            .substate_type = IRRELEVANT,
        },

        {
            .ins_len = 96,
            .ins_hex = "0105000402935deebcad35bcf27d05b431276be8fcba26312cd1d54c33ac6748a72fe427ca0"
                       "39aee5d3daebf6b132c0c58b241f25f198ddcac69421759cb1c920000000000000000000000"
                       "000000000000000000000000000000000000000005",
            .instruction_type = INS_UP,
            .substate_type = SUBSTATE_TYPE_TOKENS,
        },

        {
            .ins_len = 96,
            .ins_hex = "010500040356959464545aa2787984fe4ac76496721a22f150c0076724ad7190fe3a597bb70"
                       "39aee5d3daebf6b132c0c58b241f25f198ddcac69421759cb1c920000000000000000000000"
                       "000000000000000000000000000000000000000002",
            .instruction_type = INS_UP,
            .substate_type = SUBSTATE_TYPE_TOKENS,
        },

        {
            .ins_len = 1,
            .ins_hex = "00",
            .instruction_type = INS_END,
            .substate_type = IRRELEVANT,
        },

        {
            .ins_len = 35,
            .ins_hex = "0921010000000000000000000000000000000000000000000000000de0b6b3a7640000",
            .instruction_type = INS_SYSCALL,
            .substate_type = IRRELEVANT,
        },

        {
            .ins_len = 70,
            .ins_hex = "0105000402935deebcad35bcf27d05b431276be8fcba26312cd1d54c33ac6748a72fe427ca0"
                       "10000000000000000000000000000000000000000000000000de0b6b3a7640000",
            .instruction_type = INS_UP,
            .substate_type = SUBSTATE_TYPE_TOKENS,
        },

        {
            .ins_len = 1,
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
            .expected_tx_fee = "50684735185526206758912",
            .expected_total_xrd_amount = "1049465735185526206758912",
            .expected_hash =
                {// clang-format off
            0x89, 0xd3, 0x40, 0xc6, 0x82, 0x10, 0x4e, 0xa2,
            0x93, 0x23, 0x73, 0xf1, 0xef, 0x51, 0xc3, 0x7,
            0x8, 0xb1, 0x12, 0x14, 0x47, 0x60, 0x2e, 0x50,
            0x29, 0x3a, 0x80, 0x79, 0x62, 0xc9, 0x3e, 0xf1
                  },  // clang-format on
        }};

    do_test_parse_tx(test_vector);
}

/**
 * @brief Test of successful parsing of TX with #360 bytes and #11 instructions..
 *
 * Test parsing transaction with blob:
 * 0a0001040c7e6ad291944d3fdf50cd278651e4d20ad28536b529004008a4c3938dce092c00000003
  092100000000000000000000000000000000000000000000000abbade0b6b3a764000000046ae6ca
  1c740d4b7d1a9d07ddad52ca62226851ac9f595e390a6e5ab3bf4f626b000000000105000402935d
  eebcad35bcf27d05b431276be8fcba26312cd1d54c33ac6748a72fe427ca01000000000000000000
  00000000000000000000000000d380228a40dede9c00000105000402935deebcad35bcf27d05b431
  276be8fcba26312cd1d54c33ac6748a72fe427ca0100000000000000000000000000000000000000
  00000000004563918244f40000000921010000000000000000000000000000000000000000000000
  000de0b6b3a76400000105000402935deebcad35bcf27d05b431276be8fcba26312cd1d54c33ac67
  48a72fe427ca010000000000000000000000000000000000000000000000000de0b6b3a764000000
 *
 * Deserializes into these instructions:
 * Instructions:
|- HEADER(0, 1)
|- DOWN(SubstateId { hash: 0x0c7e6ad291944d3fdf50c
  d278651e4d20ad28536b529004008a4c3938dce092c, index: 3 })
|- SYSCALL(0x0000000000
  0000000000000000000000000000000000000abbade0b6b3a7640000)
|- END
|- DOWN(Substat
  eId { hash: 0x6ae6ca1c740d4b7d1a9d07ddad52ca62226851ac9f595e390a6e5ab3bf4f626b,
  index: 0 })
|- UP(Tokens { reserved: 0, owner: 0x0402935deebcad35bcf27d05b431276
  be8fcba26312cd1d54c33ac6748a72fe427ca, resource: 0x01, amount: U256 { raw: 99878
  3000000000000000000 } })
|- UP(Tokens { reserved: 0, owner: 0x0402935deebcad35bc
  f27d05b431276be8fcba26312cd1d54c33ac6748a72fe427ca, resource: 0x01, amount: U256
   { raw: 5000000000000000000 } })
|- END
|- SYSCALL(0x010000000000000000000000000
  000000000000000000000000de0b6b3a7640000)
|- UP(Tokens { reserved: 0, owner: 0x04
  02935deebcad35bcf27d05b431276be8fcba26312cd1d54c33ac6748a72fe427ca, resource: 0x
  01, amount: U256 { raw: 1000000000000000000 } })
|- END
 *
 * Expected hash of transaction:
 * f76aa91612e79525715cf5ab683cfbd854a0c564d6d996c9bae8da08aea2b83c
 *
 */
static void test_success_xrd_transfer_to_self(void **state) {
    (void) state;

    expected_instruction_t expected_instructions[] = {

        {
            .ins_len = 3,
            .ins_hex = "0a0001",
            .instruction_type = INS_HEADER,
            .substate_type = IRRELEVANT,
        },

        {
            .ins_len = 37,
            .ins_hex = "040c7e6ad291944d3fdf50cd278651e4d20ad28536b529004008a4c3938dce092c00000003",
            .instruction_type = INS_DOWN,
            .substate_type = IRRELEVANT,
        },

        {
            .ins_len = 35,
            .ins_hex = "092100000000000000000000000000000000000000000000000abbade0b6b3a7640000",
            .instruction_type = INS_SYSCALL,
            .substate_type = IRRELEVANT,
        },

        {
            .ins_len = 1,
            .ins_hex = "00",
            .instruction_type = INS_END,
            .substate_type = IRRELEVANT,
        },

        {
            .ins_len = 37,
            .ins_hex = "046ae6ca1c740d4b7d1a9d07ddad52ca62226851ac9f595e390a6e5ab3bf4f626b00000000",
            .instruction_type = INS_DOWN,
            .substate_type = IRRELEVANT,
        },

        {
            .ins_len = 70,
            .ins_hex = "0105000402935deebcad35bcf27d05b431276be8fcba26312cd1d54c33ac6748a72fe427ca0"
                       "100000000000000000000000000000000000000000000d380228a40dede9c0000",
            .instruction_type = INS_UP,
            .substate_type = SUBSTATE_TYPE_TOKENS,
        },

        {
            .ins_len = 70,
            .ins_hex = "0105000402935deebcad35bcf27d05b431276be8fcba26312cd1d54c33ac6748a72fe427ca0"
                       "10000000000000000000000000000000000000000000000004563918244f40000",
            .instruction_type = INS_UP,
            .substate_type = SUBSTATE_TYPE_TOKENS,
        },

        {
            .ins_len = 1,
            .ins_hex = "00",
            .instruction_type = INS_END,
            .substate_type = IRRELEVANT,
        },

        {
            .ins_len = 35,
            .ins_hex = "0921010000000000000000000000000000000000000000000000000de0b6b3a7640000",
            .instruction_type = INS_SYSCALL,
            .substate_type = IRRELEVANT,
        },

        {
            .ins_len = 70,
            .ins_hex = "0105000402935deebcad35bcf27d05b431276be8fcba26312cd1d54c33ac6748a72fe427ca0"
                       "10000000000000000000000000000000000000000000000000de0b6b3a7640000",
            .instruction_type = INS_UP,
            .substate_type = SUBSTATE_TYPE_TOKENS,
        },

        {
            .ins_len = 1,
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
            .expected_tx_fee = "50684735185526206758912",
            .expected_total_xrd_amount = "50684735185526206758912",
            .expected_hash =
                {// clang-format off
            0xf7, 0x6a, 0xa9, 0x16, 0x12, 0xe7, 0x95, 0x25,
            0x71, 0x5c, 0xf5, 0xab, 0x68, 0x3c, 0xfb, 0xd8,
            0x54, 0xa0, 0xc5, 0x64, 0xd6, 0xd9, 0x96, 0xc9,
            0xba, 0xe8, 0xda, 0x8, 0xae, 0xa2, 0xb8, 0x3c
                  },  // clang-format on
        }};

    do_test_parse_tx(test_vector);
}

/**
 * @brief Test of successful parsing of TX with #467 bytes and #13 instructions..
 *
 * Test parsing transaction with blob:
 * 0a0001040c7e6ad291944d3fdf50cd278651e4d20ad28536b529004008a4c3938dce092c00000001
  092100000000000000000000000000000000000000000000000abbade0b6b3a76400000105000402
  935deebcad35bcf27d05b431276be8fcba26312cd1d54c33ac6748a72fe427ca0100000000000000
  000000000000000000000000000000d38b4d5d456f911400000005000000000105000402935deebc
  ad35bcf27d05b431276be8fcba26312cd1d54c33ac6748a72fe427ca010000000000000000000000
  0000000000000000000000d38075ce8914caf400000eaf99885ac063393a2849d4b0df36c5ec3164
  408132526caf59f53d1239be2bf8000000000106000356959464545aa2787984fe4ac76496721a22
  f150c0076724ad7190fe3a597bb70402935deebcad35bcf27d05b431276be8fcba26312cd1d54c33
  ac6748a72fe427ca00000000000000000000000000000000000000000000000ad78ebc5ac6200000
  000921010000000000000000000000000000000000000000000000000de0b6b3a764000001050004
  02935deebcad35bcf27d05b431276be8fcba26312cd1d54c33ac6748a72fe427ca01000000000000
  0000000000000000000000000000000000000de0b6b3a764000000
 *
 * Deserializes into these instructions:
 * Instructions:
|- HEADER(0, 1)
|- DOWN(SubstateId { hash: 0x0c7e6ad291944d3fdf50c
  d278651e4d20ad28536b529004008a4c3938dce092c, index: 1 })
|- SYSCALL(0x0000000000
  0000000000000000000000000000000000000abbade0b6b3a7640000)
|- UP(Tokens { reserve
  d: 0, owner: 0x0402935deebcad35bcf27d05b431276be8fcba26312cd1d54c33ac6748a72fe42
  7ca, resource: 0x01, amount: U256 { raw: 998989000000000000000000 } })
|- END
|-
   LDOWN(0)
|- UP(Tokens { reserved: 0, owner: 0x0402935deebcad35bcf27d05b431276be
  8fcba26312cd1d54c33ac6748a72fe427ca, resource: 0x01, amount: U256 { raw: 9987890
  00000000000000000 } })
|- READ(SubstateId { hash: 0xaf99885ac063393a2849d4b0df36
  c5ec3164408132526caf59f53d1239be2bf8, index: 0 })
|- UP(PreparedStake { reserved
  : 0, validator: 0x0356959464545aa2787984fe4ac76496721a22f150c0076724ad7190fe3a59
  7bb7, owner: 0x0402935deebcad35bcf27d05b431276be8fcba26312cd1d54c33ac6748a72fe42
  7ca, amount: U256 { raw: 200000000000000000000 } })
|- END
|- SYSCALL(0x01000000
  0000000000000000000000000000000000000000000de0b6b3a7640000)
|- UP(Tokens { reser
  ved: 0, owner: 0x0402935deebcad35bcf27d05b431276be8fcba26312cd1d54c33ac6748a72fe
  427ca, resource: 0x01, amount: U256 { raw: 1000000000000000000 } })
|- END
 *
 * Expected hash of transaction:
 * 13395cb5484b04e599bc2d0de8b275a24b9f7ae8eaf0cfc6bd5a2747d3694a4b
 *
 */
static void test_success_token_transfer_and_stake(void **state) {
    (void) state;

    expected_instruction_t expected_instructions[] = {

        {
            .ins_len = 3,
            .ins_hex = "0a0001",
            .instruction_type = INS_HEADER,
            .substate_type = IRRELEVANT,
        },

        {
            .ins_len = 37,
            .ins_hex = "040c7e6ad291944d3fdf50cd278651e4d20ad28536b529004008a4c3938dce092c00000001",
            .instruction_type = INS_DOWN,
            .substate_type = IRRELEVANT,
        },

        {
            .ins_len = 35,
            .ins_hex = "092100000000000000000000000000000000000000000000000abbade0b6b3a7640000",
            .instruction_type = INS_SYSCALL,
            .substate_type = IRRELEVANT,
        },

        {
            .ins_len = 70,
            .ins_hex = "0105000402935deebcad35bcf27d05b431276be8fcba26312cd1d54c33ac6748a72fe427ca0"
                       "100000000000000000000000000000000000000000000d38b4d5d456f91140000",
            .instruction_type = INS_UP,
            .substate_type = SUBSTATE_TYPE_TOKENS,
        },

        {
            .ins_len = 1,
            .ins_hex = "00",
            .instruction_type = INS_END,
            .substate_type = IRRELEVANT,
        },

        {
            .ins_len = 5,
            .ins_hex = "0500000000",
            .instruction_type = INS_LDOWN,
            .substate_type = IRRELEVANT,
        },

        {
            .ins_len = 70,
            .ins_hex = "0105000402935deebcad35bcf27d05b431276be8fcba26312cd1d54c33ac6748a72fe427ca0"
                       "100000000000000000000000000000000000000000000d38075ce8914caf40000",
            .instruction_type = INS_UP,
            .substate_type = SUBSTATE_TYPE_TOKENS,
        },

        {
            .ins_len = 37,
            .ins_hex = "0eaf99885ac063393a2849d4b0df36c5ec3164408132526caf59f53d1239be2bf800000000",
            .instruction_type = INS_READ,
            .substate_type = IRRELEVANT,
        },

        {
            .ins_len = 102,
            .ins_hex = "0106000356959464545aa2787984fe4ac76496721a22f150c0076724ad7190fe3a597bb7040"
                       "2935deebcad35bcf27d05b431276be8fcba26312cd1d54c33ac6748a72fe427ca0000000000"
                       "0000000000000000000000000000000000000ad78ebc5ac6200000",
            .instruction_type = INS_UP,
            .substate_type = SUBSTATE_TYPE_PREPARED_STAKE,
        },

        {
            .ins_len = 1,
            .ins_hex = "00",
            .instruction_type = INS_END,
            .substate_type = IRRELEVANT,
        },

        {
            .ins_len = 35,
            .ins_hex = "0921010000000000000000000000000000000000000000000000000de0b6b3a7640000",
            .instruction_type = INS_SYSCALL,
            .substate_type = IRRELEVANT,
        },

        {
            .ins_len = 70,
            .ins_hex = "0105000402935deebcad35bcf27d05b431276be8fcba26312cd1d54c33ac6748a72fe427ca0"
                       "10000000000000000000000000000000000000000000000000de0b6b3a7640000",
            .instruction_type = INS_UP,
            .substate_type = SUBSTATE_TYPE_TOKENS,
        },

        {
            .ins_len = 1,
            .ins_hex = "00",
            .instruction_type = INS_END,
            .substate_type = IRRELEVANT,
        }};

    test_vector_t test_vector = (test_vector_t){
        .total_number_of_instructions = 13,
        .expected_instructions = expected_instructions,
        .expected_result = EXPECTED_RESULT_SUCCESS,
        .expected_success = {
            .my_public_key_hex =
                "0356959464545aa2787984fe4ac76496721a22f150c0076724ad7190fe3a597bb7",
            .expected_tx_fee = "50684735185526206758912",
            .expected_total_xrd_amount = "2048463735185526206758912",
            .expected_hash =
                {// clang-format off
            0x13, 0x39, 0x5c, 0xb5, 0x48, 0x4b, 0x4, 0xe5,
            0x99, 0xbc, 0x2d, 0xd, 0xe8, 0xb2, 0x75, 0xa2,
            0x4b, 0x9f, 0x7a, 0xe8, 0xea, 0xf0, 0xcf, 0xc6,
            0xbd, 0x5a, 0x27, 0x47, 0xd3, 0x69, 0x4a, 0x4b
                  },  // clang-format on
        }};

    do_test_parse_tx(test_vector);
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
        // cmocka_unit_test(test_failure_invalid_header_invalid_version),
        // cmocka_unit_test(test_failure_invalid_header_invalid_flag),
        // cmocka_unit_test(test_failure_no_fee_in_tx),
        // cmocka_unit_test(test_failure_invalid_syscall_too_few_bytes),
        // cmocka_unit_test(test_failure_claiming_tx_is_larger_than_sum_of_instruction_byte_count),
        // cmocka_unit_test(test_failure_claiming_tx_is_smaller_than_sum_of_instruction_byte_count),

        // // Unsupported/Invalid Instructions
        // cmocka_unit_test(test_failure_unrecognized_instruction),
        // cmocka_unit_test(test_failure_unsupported_instruction_vdown_0x02),
        // cmocka_unit_test(test_failure_unsupported_instruction_vdownarg_0x03),
        // cmocka_unit_test(test_failure_unsupported_instruction_sig_0x07),
        // cmocka_unit_test(test_failure_unsupported_instruction_downall_0x08),

        // // Unsupported/Invalid Substate Types
        // cmocka_unit_test(test_failure_unrecognized_substate_type),
        // cmocka_unit_test(test_failure_unsupported_substate_type_re_address_0x00),
        // cmocka_unit_test(test_failure_unsupported_substate_type_token_definition_0x02),
        // cmocka_unit_test(test_failure_unsupported_substate_type_validator_0x05),
        // cmocka_unit_test(test_failure_unsupported_substate_type_unique_0x06),
        // cmocka_unit_test(test_failure_unsupported_substate_type_exiting_stake_0x0e),

        // // Failed to parse tokens
        // // Invalid RRI
        // cmocka_unit_test(test_failure_parse_tokens_invalid_rri_unrecognized_address_type_0xff),
        // cmocka_unit_test(test_failure_parse_tokens_invalid_rri_usupported_address_type_system_0x00),
        // cmocka_unit_test(test_failure_parse_tokens_invalid_rri_hashed_key_too_short),
        // cmocka_unit_test(test_failure_parse_tokens_invalid_rri_incompatible_address_type),
        // // Invalid Owner
        // cmocka_unit_test(test_failure_parse_tokens_invalid_owner_address_type_0x01_system),
        // cmocka_unit_test(test_failure_parse_tokens_invalid_owner_address_type_0x03_hashed_pubkey),
        // cmocka_unit_test(test_failure_parse_tokens_invalid_owner_too_few_bytes),

    };

    int status = 0;

    status += cmocka_run_group_tests_name("RRI", rri_formatting, NULL, NULL);
    status += cmocka_run_group_tests_name("Valid transactions", success_complex_tx, NULL, NULL);
    // status += cmocka_run_group_tests_name("Invalid transactions", failing_txs, NULL, NULL);
    return status;
}
