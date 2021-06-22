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
#include "instruction/substate/stake_share.h"

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

/**
 * @brief Test parsing a tx with 9 instructions.
 *
 * Hex string for transaction below:
 * 0x0a000104374c00efbe61f645a8b35d7746e106afa7422877e5d607975b6018e0a1aa6bf0000000040921000000000000000000000000000000000000000000000000000000000000000002010301040377bac8066e51cd0d6b320c338d5abbcdbcca25572b6b3eee9443eafc92106bba000000000000000000000000000000000000000000000001158e460913cffffe000500000003010301040377bac8066e51cd0d6b320c338d5abbcdbcca25572b6b3eee9443eafc92106bba0000000000000000000000000000000000000000000000008ac7230489e7fffe0104040377bac8066e51cd0d6b320c338d5abbcdbcca25572b6b3eee9443eafc92106bba02f19b2d095a553f3a41da4a8dc1f8453dfbdc733c5aece8b128b7d7999ae247a50000000000000000000000000000000000000000000000008ac7230489e8000000
 *
 * String representation of instructions of transaction below:
 *
 * Instructions:
 * |- HEADER(0, 1)
 * |- DOWN(SubstateId { hash:
 * 0x374c00efbe61f645a8b35d7746e106afa7422877e5d607975b6018e0a1aa6bf0, index: 4 })
 * |- SYSCALL(0x000000000000000000000000000000000000000000000000000000000000000002)
 * |- UP(Tokens { rri: 0x01, owner:
 * 0x040377bac8066e51cd0d6b320c338d5abbcdbcca25572b6b3eee9443eafc92106bba, amount: U256 { raw:
 * 19999999999999999998 } })
 * |- END
 * |- LDOWN(3)
 * |- UP(Tokens { rri: 0x01, owner:
 * 0x040377bac8066e51cd0d6b320c338d5abbcdbcca25572b6b3eee9443eafc92106bba, amount: U256 { raw:
 * 9999999999999999998 } })
 * |- UP(PreparedStake { owner:
 * 0x040377bac8066e51cd0d6b320c338d5abbcdbcca25572b6b3eee9443eafc92106bba, delegate:
 * 0x02f19b2d095a553f3a41da4a8dc1f8453dfbdc733c5aece8b128b7d7999ae247a5, amount: U256 { raw:
 * 10000000000000000000 } })
 * |- END
 *
 * Further prettified human readable  representation of instructions of tx below:
 *
 * Instructions:
 * |- HEADER(0, 1)
 * |- DOWN(SubstateId { hash:
 * 0x374c00efbe61f645a8b35d7746e106afa7422877e5d607975b6018e0a1aa6bf0, index: 4 })
 * |- SYSCALL(0x000000000000000000000000000000000000000000000000000000000000000002)
 * |
 * |- UP(Tokens {
 * |--- rri: xrd_rb1qya85pwq,
 * |--- owner: brx1qsph0wkgqeh9rngddveqcvudt2aum0x2y4tjk6e7a62y86hujggxhws07tsg3,
 * |--- amount: 19.0000
 * |- })
 * |
 * |- END
 * |- LDOWN(3)
 * |
 * |- UP(Tokens {
 * |--- rri: xrd_rb1qya85pwq,
 * |--- owner: brx1qsph0wkgqeh9rngddveqcvudt2aum0x2y4tjk6e7a62y86hujggxhws07tsg3,
 * |--- amount: 9.0000
 * |- })
 * |
 * |- UP(PreparedStake {
 * |--- owner: brx1qsph0wkgqeh9rngddveqcvudt2aum0x2y4tjk6e7a62y86hujggxhws07tsg3,
 * |--- delegate: vb1qtcektgftf2n7wjpmf9gms0cg57lhhrn83dwe6939zma0xv6ufr62ry5ycv,
 * |--- amount: 10.0000
 * |- })
 * |
 * |- END
 */
static void test_success_transfer_transfer_stake(void **state) {
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
            .ins_hex = "04374c00efbe61f645a8b35d7746e106afa7422877e5d607975b6018e0a1aa6bf000000004",
            .instruction_type = INS_DOWN,
            .substate_type = IRRELEVANT,
        },
        {
            .ins_len = 35,
            .ins_hex = "0921000000000000000000000000000000000000000000000000000000000000000002",
            .instruction_type = INS_SYSCALL,
            .substate_type = IRRELEVANT,
        },
        {
            .ins_len = 69,
            .ins_hex = "010301040377bac8066e51cd0d6b320c338d5abbcdbcca25572b6b3eee9443eafc92106bba0"
                       "00000000000000000000000000000000000000000000001158e460913cffffe",
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
            .ins_hex = "0500000003",
            .instruction_type = INS_LDOWN,
            .substate_type = IRRELEVANT,
        },
        {
            .ins_len = 69,
            .ins_hex = "010301040377bac8066e51cd0d6b320c338d5abbcdbcca25572b6b3eee9443eafc92106bba0"
                       "000000000000000000000000000000000000000000000008ac7230489e7fffe",
            .instruction_type = INS_UP,
            .substate_type = SUBSTATE_TYPE_TOKENS,
        },
        {
            .ins_len = 101,
            .ins_hex = "0104040377bac8066e51cd0d6b320c338d5abbcdbcca25572b6b3eee9443eafc92106bb"
                       "a02f19b2d095a553f3a41da4a8dc1f8453dfbdc733c5aece8b128b7d7999ae247a50000"
                       "000000000000000000000000000000000000000000008ac7230489e80000",
            .instruction_type = INS_UP,
            .substate_type = SUBSTATE_TYPE_PREPARED_STAKE,
        },
        {
            .ins_len = 1,
            .ins_hex = "00",
            .instruction_type = INS_END,
            .substate_type = IRRELEVANT,
        },
    };

    test_vector_t test_vector = (test_vector_t){
        .total_number_of_instructions = 9,
        .expected_instructions = expected_instructions,
        .expected_result = EXPECTED_RESULT_SUCCESS,
        .expected_success = {
            .my_public_key_hex =
                "026d5e07cfde5df84b5ef884b629d28d15b0f6c66be229680699767cd57c618288",
            .expected_tx_fee = "2",
            .expected_total_xrd_amount = "29999999999999999998",
            .expected_hash =
                {
                    // clang-format off
    	        0x83, 0xf4, 0x54, 0x4f, 0xf1, 0xfb, 0xab, 0xc7,
            	0xbe, 0x39, 0xc6, 0xf5, 0x31, 0xc3, 0xf3, 0x7f,
            	0xc5, 0x0e, 0x0a, 0x0b, 0x65, 0x3a, 0xfd, 0xb2,
            	0x2c, 0xc9, 0xf8, 0xe8, 0xaa, 0x46, 0x1f, 0xc9
                    // clang-format on
                },  //         expected hash:
                    //         83f4544ff1fbabc7be39c6f531c3f37fc50e0a0b653afdb22cc9f8e8aa461fc9

        }};

    do_test_parse_tx(test_vector);
}

/**
 * @brief
 * BLOB
 * 0a0001045d375643dded796e8d3526dcae7a068c642e35fb9931688f56ea20b56289330f0000000309210000000000000000000000000000000000000000000000000000000000deadbeef0103010402ed0eeaf54a79df88f12f251f22b88df00afaad43497f448620353a94e5c2e155000000000000000000000000000000000000000000000001158e460913cffffe0005000000020103010402ed0eeaf54a79df88f12f251f22b88df00afaad43497f448620353a94e5c2e1550000000000000000000000000000000000000000000000008ac7230489e7fffe01040402ed0eeaf54a79df88f12f251f22b88df00afaad43497f448620353a94e5c2e15502fd72e14bae5305db65f51d723e0a68a54a49dc85d0875b44d3cf1e80413de8870000000000000000000000000000000000000000000000008ac7230489e800000005000000050103010402ed0eeaf54a79df88f12f251f22b88df00afaad43497f448620353a94e5c2e1550000000000000000000000000000000000000000000000008ac7230489e7fffd01030104036b062b0044f412f30a973947e5e986629669d055b78fcfbb68a63211462ed0f7000000000000000000000000000000000000000000000000000000000000000100

      Instructions:
      |- HEADER(0, 1)
      |- DOWN(SubstateId { hash:
 0x5d375643dded796e8d3526dcae7a068c642e35fb9931688f56ea20b56289330f, index: 3 })
      |- SYSCALL(0x0000000000000000000000000000000000000000000000000000000000deadbeef)
      |- UP(Tokens { rri: 0x01, owner:
 0x0402ed0eeaf54a79df88f12f251f22b88df00afaad43497f448620353a94e5c2e155, amount: U256 { raw:
 19999999999999999998 } })
      |- END
      |- LDOWN(2)
      |- UP(Tokens { rri: 0x01, owner:
 0x0402ed0eeaf54a79df88f12f251f22b88df00afaad43497f448620353a94e5c2e155, amount: U256 { raw:
 9999999999999999998 } })
      |- UP(PreparedStake { owner:
 0x0402ed0eeaf54a79df88f12f251f22b88df00afaad43497f448620353a94e5c2e155, delegate:
 0x02fd72e14bae5305db65f51d723e0a68a54a49dc85d0875b44d3cf1e80413de887, amount: U256 { raw:
 10000000000000000000 } })
      |- END
      |- LDOWN(5)
      |- UP(Tokens { rri: 0x01, owner:
 0x0402ed0eeaf54a79df88f12f251f22b88df00afaad43497f448620353a94e5c2e155, amount: U256 { raw:
 9999999999999999997 } })
      |- UP(Tokens { rri: 0x01, owner:
 0x04036b062b0044f412f30a973947e5e986629669d055b78fcfbb68a63211462ed0f7, amount: U256 { raw: 1 }
 })
      |- END


    More human readable

      HEADER(0, 1)
      DOWN(SubstateId { hash:
 0x5d375643dded796e8d3526dcae7a068c642e35fb9931688f56ea20b56289330f, index: 3 })
      SYSCALL(0x0000000000000000000000000000000000000000000000000000000000deadbeef)
      UP(Tokens { rri: xrd_rb1qya85pwq, owner:
 brx1qspw6rh27498nhug7yhj28ezhzxlqzh644p5jl6yscsr2w55uhpwz4gcpqecd, amount: 19.0000 })
      END
      LDOWN(2)
      UP(Tokens { rri: xrd_rb1qya85pwq, owner:
 brx1qspw6rh27498nhug7yhj28ezhzxlqzh644p5jl6yscsr2w55uhpwz4gcpqecd, amount: 9.0000 })
      UP(PreparedStake { owner:
 brx1qspw6rh27498nhug7yhj28ezhzxlqzh644p5jl6yscsr2w55uhpwz4gcpqecd, delegate:
 vb1qt7h9c2t4efstkm975why0s2dzj55jwushggwk6y6083aqzp8h5gwr7x4gz, amount: 10.0000 }) END LDOWN(5)
      UP(Tokens { rri: xrd_rb1qya85pwq, owner:
 brx1qspw6rh27498nhug7yhj28ezhzxlqzh644p5jl6yscsr2w55uhpwz4gcpqecd, amount: 9.0000 })
      UP(Tokens { rri: xrd_rb1qya85pwq, owner:
 brx1qspkkp3tqpz0gyhnp2tnj3l9axrx99nf6p2m0r70hd52vvs3gchdpacsadyal, amount: 0.0000 })
      END
 *
 * @param state
 */
static void test_success_transfer_transfer_stake_transfer_with_change(void **state) {
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
            .ins_hex = "045d375643dded796e8d3526dcae7a068c642e35fb9931688f56ea20b56289330f00000003",
            .instruction_type = INS_DOWN,
            .substate_type = IRRELEVANT,
        },
        {
            .ins_len = 35,
            .ins_hex = "09210000000000000000000000000000000000000000000000000000000000deadbeef",
            .instruction_type = INS_SYSCALL,
            .substate_type = IRRELEVANT,
        },
        {
            .ins_len = 69,
            .ins_hex = "0103010402ed0eeaf54a79df88f12f251f22b88df00afaad43497f448620353a94e5c2e1550"
                       "00000000000000000000000000000000000000000000001158e460913cffffe",
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
            .ins_hex = "0500000002",
            .instruction_type = INS_LDOWN,
            .substate_type = IRRELEVANT,
        },
        {
            .ins_len = 69,
            .ins_hex = "0103010402ed0eeaf54a79df88f12f251f22b88df00afaad43497f448620353a94e5c2e1550"
                       "000000000000000000000000000000000000000000000008ac7230489e7fffe",
            .instruction_type = INS_UP,
            .substate_type = SUBSTATE_TYPE_TOKENS,
        },
        {
            .ins_len = 101,
            .ins_hex = "01040402ed0eeaf54a79df88f12f251f22b88df00afaad43497f448620353a94e5c2e15502f"
                       "d72e14bae5305db65f51d723e0a68a54a49dc85d0875b44d3cf1e80413de887000000000000"
                       "0000000000000000000000000000000000008ac7230489e80000",
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
            .ins_len = 5,
            .ins_hex = "0500000005",
            .instruction_type = INS_LDOWN,
            .substate_type = IRRELEVANT,
        },
        {
            .ins_len = 69,
            .ins_hex = "0103010402ed0eeaf54a79df88f12f251f22b88df00afaad43497f448620353a94e5c2e1550"
                       "000000000000000000000000000000000000000000000008ac7230489e7fffd",
            .instruction_type = INS_UP,
            .substate_type = SUBSTATE_TYPE_TOKENS,
        },
        {
            .ins_len = 69,
            .ins_hex = "01030104036b062b0044f412f30a973947e5e986629669d055b78fcfbb68a63211462ed0f70"
                       "000000000000000000000000000000000000000000000000000000000000001",
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
        .total_number_of_instructions = 13,
        .expected_instructions = expected_instructions,
        .expected_result = EXPECTED_RESULT_SUCCESS,
        .expected_success = {
            .my_public_key_hex =
                "036b062b0044f412f30a973947e5e986629669d055b78fcfbb68a63211462ed0f7",
            .expected_tx_fee = "3735928559",
            .expected_total_xrd_amount = "40000000003735928552",
            .expected_hash =
                {
                    // clang-format off
      0x42, 0x32, 0x5f, 0x68, 0xc1, 0x60, 0x71, 0xd0,
      0xf2, 0x44, 0xbe, 0x9a, 0x73, 0x82, 0xb3, 0x4e,
      0x52, 0x03, 0x7c, 0x4c, 0x6b, 0xa6, 0x35, 0x43,
      0xfc, 0x68, 0x56, 0x22, 0x0f, 0x42, 0x27, 0x0d
                    // clang-format on
                },  //         expected hash:
                    //         42325f68c16071d0f244be9a7382b34e52037c4c6ba63543fc6856220f42270d
        }};

    do_test_parse_tx(test_vector);
}

/**
 * @brief
 *
 * Blob
 0a000104c1e268b8b61ce5688d039aefa1e5ea6612a6c4d3b497713582916b533d6c5028000000030921000000000000000000000000000000000000000000000038821089088b6063da1801030104035c8522494136cab2c7445cd485a905338fa9191d0d3314cf0e3b60a792119f2b000000000000000000000000000000000000000000000001158e460913cffffe00050000000201030104035c8522494136cab2c7445cd485a905338fa9191d0d3314cf0e3b60a792119f2b000000000000000000000000000000000000000000000001158e460913cffffd01030104022c4f0832c24ebc6477005c397fa51e8de0710098b816d43a85332658c7a21411000000000000000000000000000000000000000000000000000000000000000100050000000501030104035c8522494136cab2c7445cd485a905338fa9191d0d3314cf0e3b60a792119f2b0000000000000000000000000000000000000000000000008ac7230489e7fffd010404035c8522494136cab2c7445cd485a905338fa9191d0d3314cf0e3b60a792119f2b037bf52ffd736eda6554b3b7b03eae3f9e2bd9b4b1c11e73355191403ff96961ac0000000000000000000000000000000000000000000000008ac7230489e8000000

      Instructions:
      |- HEADER(0, 1)
      |- DOWN(SubstateId { hash:
 0xc1e268b8b61ce5688d039aefa1e5ea6612a6c4d3b497713582916b533d6c5028, index: 3 })
      |- SYSCALL(0x000000000000000000000000000000000000000000000038821089088b6063da18)
      |- UP(Tokens { rri: 0x01, owner:
 0x04035c8522494136cab2c7445cd485a905338fa9191d0d3314cf0e3b60a792119f2b, amount: U256 { raw:
 19999999999999999998 } })
      |- END
      |- LDOWN(2)
      |- UP(Tokens { rri: 0x01, owner:
 0x04035c8522494136cab2c7445cd485a905338fa9191d0d3314cf0e3b60a792119f2b, amount: U256 { raw:
 19999999999999999997 } })
      |- UP(Tokens { rri: 0x01, owner:
 0x04022c4f0832c24ebc6477005c397fa51e8de0710098b816d43a85332658c7a21411, amount: U256 { raw: 1 }
 })
      |- END
      |- LDOWN(5)
      |- UP(Tokens { rri: 0x01, owner:
 0x04035c8522494136cab2c7445cd485a905338fa9191d0d3314cf0e3b60a792119f2b, amount: U256 { raw:
 9999999999999999997 } })
      |- UP(PreparedStake { owner:
 0x04035c8522494136cab2c7445cd485a905338fa9191d0d3314cf0e3b60a792119f2b, delegate:
 0x037bf52ffd736eda6554b3b7b03eae3f9e2bd9b4b1c11e73355191403ff96961ac, amount: U256 { raw:
 10000000000000000000 } })
      |- END


      More human readable:

      HEADER(0, 1)
      DOWN(SubstateId { hash:
 0xc1e268b8b61ce5688d039aefa1e5ea6612a6c4d3b497713582916b533d6c5028, index: 3 })
      SYSCALL(0x000000000000000000000000000000000000000000000038821089088b6063da18)
      UP(Tokens { rri: xrd_rb1qya85pwq, owner:
 brx1qsp4epfzf9qndj4jcaz9e4y94yzn8rafryws6vc5eu8rkc98jgge72cddfkp7, amount: 19.0000 })
      END
      LDOWN(2)
      UP(Tokens { rri: xrd_rb1qya85pwq, owner:
 brx1qsp4epfzf9qndj4jcaz9e4y94yzn8rafryws6vc5eu8rkc98jgge72cddfkp7, amount: 19.0000 })
      UP(Tokens { rri: xrd_rb1qya85pwq, owner:
 brx1qspzcncgxtpya0rywuq9cwtl550gmcr3qzvts9k582znxfjcc73pgygp9c86v, amount: 0.0000 })
      END
      LDOWN(5)
      UP(Tokens { rri: xrd_rb1qya85pwq, owner:
 brx1qsp4epfzf9qndj4jcaz9e4y94yzn8rafryws6vc5eu8rkc98jgge72cddfkp7, amount: 9.0000 })
      UP(PreparedStake { owner:
 brx1qsp4epfzf9qndj4jcaz9e4y94yzn8rafryws6vc5eu8rkc98jgge72cddfkp7, delegate:
 vb1qdal2tlawdhd5e25kwmmq04w870zhkd5k8q3uue42xg5q0led9s6cxpe65y, amount: 10.0000 }) END

 *
 */
static void test_success_transfer_transfer_with_change_transfer_stake(void **state) {
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
            .ins_len = 69,
            .ins_hex = "01030104035c8522494136cab2c7445cd485a905338fa9191d0d3314cf0e3b60a792119f2b0"
                       "00000000000000000000000000000000000000000000001158e460913cffffe",
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
            .ins_hex = "0500000002",
            .instruction_type = INS_LDOWN,
            .substate_type = IRRELEVANT,
        },
        {
            .ins_len = 69,
            .ins_hex = "01030104035c8522494136cab2c7445cd485a905338fa9191d0d3314cf0e3b60a792119f2b0"
                       "00000000000000000000000000000000000000000000001158e460913cffffd",
            .instruction_type = INS_UP,
            .substate_type = SUBSTATE_TYPE_TOKENS,
        },
        {
            .ins_len = 69,
            .ins_hex = "01030104022c4f0832c24ebc6477005c397fa51e8de0710098b816d43a85332658c7a214110"
                       "000000000000000000000000000000000000000000000000000000000000001",
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
            .ins_hex = "0500000005",
            .instruction_type = INS_LDOWN,
            .substate_type = IRRELEVANT,
        },
        {
            .ins_len = 69,
            .ins_hex = "01030104035c8522494136cab2c7445cd485a905338fa9191d0d3314cf0e3b60a792119f2b0"
                       "000000000000000000000000000000000000000000000008ac7230489e7fffd",
            .instruction_type = INS_UP,
            .substate_type = SUBSTATE_TYPE_TOKENS,
        },
        {
            .ins_len = 101,
            .ins_hex = "010404035c8522494136cab2c7445cd485a905338fa9191d0d3314cf0e3b60a792119f2b037"
                       "bf52ffd736eda6554b3b7b03eae3f9e2bd9b4b1c11e73355191403ff96961ac000000000000"
                       "0000000000000000000000000000000000008ac7230489e80000",
            .instruction_type = INS_UP,
            .substate_type = SUBSTATE_TYPE_PREPARED_STAKE,
        },
        {
            .ins_len = 1,
            .ins_hex = "00",
            .instruction_type = INS_END,
            .substate_type = IRRELEVANT,
        },
    };

    test_vector_t test_vector = (test_vector_t){
        .total_number_of_instructions = 13,
        .expected_instructions = expected_instructions,
        .expected_result = EXPECTED_RESULT_SUCCESS,
        .expected_success =
            {
                .my_public_key_hex =
                    "022c4f0832c24ebc6477005c397fa51e8de0710098b816d43a85332658c7a21411",
                .expected_tx_fee = "266851791263253500516888",
                .expected_total_xrd_amount = "266901791263253500516880",
                .expected_hash =
                    {
                        // clang-format off
      0xda, 0xbb, 0xe3, 0xc3, 0x60, 0x1b, 0x3b, 0xbc,
      0x58, 0x63, 0x36, 0x8e, 0x8e, 0x8f, 0x06, 0x1c,
      0x24, 0x42, 0x0a, 0x9b, 0x2e, 0x06, 0x58, 0xad,
      0x50, 0xa7, 0x40, 0xee, 0xb6, 0x16, 0x02, 0xde
                        // clang-format on
                    },  //         expected hash:
                        //         dabbe3c3601b3bbc5863368e8e8f061c24420a9b2e0658ad50a740eeb61602de
            },
    };

    do_test_parse_tx(test_vector);
}

/**
 * @brief
 *
 * Blob
 *
 0a00010414f4235a478a63f7c17795bb482ed22efb8bcbe5239d3a5544f33b26f308747500000001092100000000000000000000000000000000000000000000000000000000000000303901030104033b8c4cfdf815828620bd5ed254225f2be4ecfcd1b7c72d096f385835ca1c8d700000000000000000000000000000000000000000000000008ac7230489e7fffc00045e01ca4385fe4ba31d3649ae7cc746446d46c4405064bf7c6d4faa853586eab700000007010d031fa3fe2db67d482ef3b3b6f6facf874cf1502af8a463d8ac75f378a09d78f01204033b8c4cfdf815828620bd5ed254225f2be4ecfcd1b7c72d096f385835ca1c8d700000000000000000000000000000000000000000000000008ac7230489e8000000050000000201030104033b8c4cfdf815828620bd5ed254225f2be4ecfcd1b7c72d096f385835ca1c8d700000000000000000000000000000000000000000000000008ac7230489e7fffb01030104039af69ffd4752e60d0f584f4ce39526dd855e1c35293473f683de09f6b19e4c96000000000000000000000000000000000000000000000000000000000000000100

      Instructions:
      |- HEADER(0, 1)
      |- DOWN(SubstateId { hash:
0x14f4235a478a63f7c17795bb482ed22efb8bcbe5239d3a5544f33b26f3087475, index: 1 })
      |- SYSCALL(0x000000000000000000000000000000000000000000000000000000000000003039)
      |- UP(Tokens { rri: 0x01, owner:
 0x04033b8c4cfdf815828620bd5ed254225f2be4ecfcd1b7c72d096f385835ca1c8d70, amount: U256 { raw:
 9999999999999999996 } })
      |- END
      |- DOWN(SubstateId { hash:
0x5e01ca4385fe4ba31d3649ae7cc746446d46c4405064bf7c6d4faa853586eab7, index: 7 })
      |- UP(PreparedUnstake { delegate:
 0x031fa3fe2db67d482ef3b3b6f6facf874cf1502af8a463d8ac75f378a09d78f012, owner:
 0x04033b8c4cfdf815828620bd5ed254225f2be4ecfcd1b7c72d096f385835ca1c8d70, amount: U256 { raw:
 10000000000000000000 } })
      |- END
      |- LDOWN(2)
      |- UP(Tokens { rri: 0x01, owner:
 0x04033b8c4cfdf815828620bd5ed254225f2be4ecfcd1b7c72d096f385835ca1c8d70, amount: U256 { raw:
 9999999999999999995 } })
      |- UP(Tokens { rri: 0x01, owner:
 0x04039af69ffd4752e60d0f584f4ce39526dd855e1c35293473f683de09f6b19e4c96, amount: U256 { raw: 1 }
})
      |- END

      More human readable:

*  HEADER(0, 1)
*  DOWN(SubstateId { hash: 0x14f4235a478a63f7c17795bb482ed22efb8bcbe5239d3a5544f33b26f3087475,
index: 1 })
* SYSCALL(0x000000000000000000000000000000000000000000000000000000000000003039)
 * UP(Tokens{ rri: xrd_rb1qya85pwq, owner:
brx1qspnhrzvlhuptq5xyz74a5j5yf0jhe8vlngm03edp9hnskp4egwg6uq0hrnd8, amount: 9.0000 })
 * END
 * DOWN(SubstateId { hash: 0x5e01ca4385fe4ba31d3649ae7cc746446d46c4405064bf7c6d4faa853586eab7,
index: 7 })
 * UP(PreparedUnstake { owner:
brx1qspnhrzvlhuptq5xyz74a5j5yf0jhe8vlngm03edp9hnskp4egwg6uq0hrnd8, delegate:
vb1qv068l3dke75sthnkwm0d7k0sax0z5p2lzjx8k9vwheh3gya0rcpynlr3g7, amount: 10.0000 })
 * END
 * LDOWN(2)
 * UP(Tokens { rri: xrd_rb1qya85pwq, owner:
brx1qspnhrzvlhuptq5xyz74a5j5yf0jhe8vlngm03edp9hnskp4egwg6uq0hrnd8, amount: 9.0000 })
 * UP(Tokens { rri: xrd_rb1qya85pwq, owner:
brx1qspe4a5ll4r49esdpavy7n8rj5ndmp27rs6jjdrn76pauz0kkx0ye9sw2a6hz, amount: 0.0000 })
 * END
 */
static void test_success_transfer_unstake_transfer_with_change(void **state) {
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
            .ins_hex = "0414f4235a478a63f7c17795bb482ed22efb8bcbe5239d3a5544f33b26f308747500000001",
            .instruction_type = INS_DOWN,
            .substate_type = IRRELEVANT,
        },
        {
            .ins_len = 35,
            .ins_hex = "0921000000000000000000000000000000000000000000000000000000000000003039",
            .instruction_type = INS_SYSCALL,
            .substate_type = IRRELEVANT,
        },
        {
            .ins_len = 69,
            .ins_hex = "01030104033b8c4cfdf815828620bd5ed254225f2be4ecfcd1b7c72d096f385835ca1c8d700"
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
        {
            .ins_len = 37,
            .ins_hex = "045e01ca4385fe4ba31d3649ae7cc746446d46c4405064bf7c6d4faa853586eab700000007",
            .instruction_type = INS_DOWN,
            .substate_type = IRRELEVANT,
        },
        {
            .ins_len = 101,
            .ins_hex = "010d031fa3fe2db67d482ef3b3b6f6facf874cf1502af8a463d8ac75f378a09d78f01204033"
                       "b8c4cfdf815828620bd5ed254225f2be4ecfcd1b7c72d096f385835ca1c8d70000000000000"
                       "0000000000000000000000000000000000008ac7230489e80000",
            .instruction_type = INS_UP,
            .substate_type = SUBSTATE_TYPE_PREPARED_UNSTAKE,
        },
        {
            .ins_len = 1,
            .ins_hex = "00",
            .instruction_type = INS_END,
            .substate_type = IRRELEVANT,
        },
        {
            .ins_len = 5,
            .ins_hex = "0500000002",
            .instruction_type = INS_LDOWN,
            .substate_type = IRRELEVANT,
        },
        {
            .ins_len = 69,
            .ins_hex = "01030104033b8c4cfdf815828620bd5ed254225f2be4ecfcd1b7c72d096f385835ca1c8d700"
                       "000000000000000000000000000000000000000000000008ac7230489e7fffb",
            .instruction_type = INS_UP,
            .substate_type = SUBSTATE_TYPE_TOKENS,
        },
        {
            .ins_len = 69,
            .ins_hex = "01030104039af69ffd4752e60d0f584f4ce39526dd855e1c35293473f683de09f6b19e4c960"
                       "000000000000000000000000000000000000000000000000000000000000001",
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
        .total_number_of_instructions = 12,
        .expected_instructions = expected_instructions,
        .expected_result = EXPECTED_RESULT_SUCCESS,
        .expected_success =
            {
                .my_public_key_hex =
                    "039af69ffd4752e60d0f584f4ce39526dd855e1c35293473f683de09f6b19e4c96",
                .expected_tx_fee = "12345",
                .expected_total_xrd_amount = "20000000000000012336",
                .expected_hash =
                    {
                        // clang-format off
      0xde, 0x9e, 0x42, 0xd3, 0x9c, 0x8a, 0x23, 0xbd,
      0x39, 0xa7, 0xde, 0xc8, 0x0a, 0xa3, 0x13, 0xed,
      0x3e, 0x0c, 0x70, 0x95, 0x87, 0x3f, 0xc9, 0xf7,
      0x10, 0x4e, 0x48, 0x1b, 0x43, 0x20, 0x68, 0xc4
                        // clang-format on
                    },  //         expected hash:
                        //         de9e42d39c8a23bd39a7dec80aa313ed3e0c7095873fc9f7104e481b432068c4
            },
    };

    do_test_parse_tx(test_vector);
}

/**
 * @brief
 * Blob
 *
 0a000104e31133f949d9d4a453c189e8b7c3b016215513f50b2ec9809b19f950954cbf0400000001092100000000000000000000000000000000000000000000000000000000003ade68b10103010403a8791ee326620a8b0d5ba636eb0422122c577698cbdb1ea97a0d3d56c33c60be0000000000000000000000000000000000000000000000008ac7230489e7fffc0005000000020103010403a8791ee326620a8b0d5ba636eb0422122c577698cbdb1ea97a0d3d56c33c60be0000000000000000000000000000000000000000000000008ac7230489e7fffb0103010402b8777eab54ba8818cb82376a5798c9c7a025c216fb05266e794cd8c5f0dd4d7a00000000000000000000000000000000000000000000000000000000000000010004361a8ec30813bafdf3b547482353080cc6b7cbd8e893496fa141d9915ae180c300000007010d02ec11f6184839402b78f5a6fbe3e5eddf41cb999ac9c3ae0cdb324ab01f8e3f200403a8791ee326620a8b0d5ba636eb0422122c577698cbdb1ea97a0d3d56c33c60be0000000000000000000000000000000000000000000000008ac7230489e8000000

      Instructions:
      |- HEADER(0, 1)
      |- DOWN(SubstateId { hash:
 0xe31133f949d9d4a453c189e8b7c3b016215513f50b2ec9809b19f950954cbf04, index: 1 })
      |- SYSCALL(0x00000000000000000000000000000000000000000000000000000000003ade68b1)
      |- UP(Tokens { rri: 0x01, owner:
 0x0403a8791ee326620a8b0d5ba636eb0422122c577698cbdb1ea97a0d3d56c33c60be, amount: U256 { raw:
 9999999999999999996 } })
      |- END
      |- LDOWN(2)
      |- UP(Tokens { rri: 0x01, owner:
 0x0403a8791ee326620a8b0d5ba636eb0422122c577698cbdb1ea97a0d3d56c33c60be, amount: U256 { raw:
 9999999999999999995 } })
      |- UP(Tokens { rri: 0x01, owner:
 0x0402b8777eab54ba8818cb82376a5798c9c7a025c216fb05266e794cd8c5f0dd4d7a, amount: U256 { raw: 1 }
 })
      |- END
      |- DOWN(SubstateId { hash:
 0x361a8ec30813bafdf3b547482353080cc6b7cbd8e893496fa141d9915ae180c3, index: 7 })
      |- UP(PreparedUnstake { delegate:
 0x02ec11f6184839402b78f5a6fbe3e5eddf41cb999ac9c3ae0cdb324ab01f8e3f20, owner:
 0x0403a8791ee326620a8b0d5ba636eb0422122c577698cbdb1ea97a0d3d56c33c60be, amount: U256 { raw:
 10000000000000000000 } })
      |- END

      Human readable:

      *HEADER(0, 1)
      * DOWN(SubstateId { hash:
 0xe31133f949d9d4a453c189e8b7c3b016215513f50b2ec9809b19f950954cbf04, index: 1 })
      * SYSCALL(0x00000000000000000000000000000000000000000000000000000000003ade68b1)
      * UP(Tokens { rri: xrd_rb1qya85pwq, owner:
 brx1qsp6s7g7uvnxyz5tp4d6vdhtqs3pytzhw6vvhkc749aq602kcv7xp0s5whvx8, amount: 9.0000 })
      * END
      * LDOWN(2)
      * UP(Tokens { rri: xrd_rb1qya85pwq, owner:
 brx1qsp6s7g7uvnxyz5tp4d6vdhtqs3pytzhw6vvhkc749aq602kcv7xp0s5whvx8, amount: 9.0000 })
      * UP(Tokens { rri: xrd_rb1qya85pwq, owner:
 brx1qsptsam74d2t4zqcewprw6jhnryu0gp9cgt0kpfxdeu5ekx97rw567sz8utwe, amount: 0.0000 })
      * END
      * DOWN(SubstateId { hash:
 0x361a8ec30813bafdf3b547482353080cc6b7cbd8e893496fa141d9915ae180c3, index: 7 })
      * UP(PreparedUnstake { owner:
 brx1qsp6s7g7uvnxyz5tp4d6vdhtqs3pytzhw6vvhkc749aq602kcv7xp0s5whvx8, delegate:
 vb1qtkprascfqu5q2mc7kn0hcl9ah05rjuentyu8tsvmvey4vql3cljqltylt4, amount: 10.0000 })
      * END
 */
static void test_success_transfer_transfer_with_change_unstake(void **state) {
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
            .ins_hex = "04e31133f949d9d4a453c189e8b7c3b016215513f50b2ec9809b19f950954cbf0400000001",
            .instruction_type = INS_DOWN,
            .substate_type = IRRELEVANT,
        },
        {
            .ins_len = 35,
            .ins_hex = "092100000000000000000000000000000000000000000000000000000000003ade68b1",
            .instruction_type = INS_SYSCALL,
            .substate_type = IRRELEVANT,
        },
        {
            .ins_len = 69,
            .ins_hex = "0103010403a8791ee326620a8b0d5ba636eb0422122c577698cbdb1ea97a0d3d56c33c60be0"
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
        {
            .ins_len = 5,
            .ins_hex = "0500000002",
            .instruction_type = INS_LDOWN,
            .substate_type = IRRELEVANT,
        },
        {
            .ins_len = 69,
            .ins_hex = "0103010403a8791ee326620a8b0d5ba636eb0422122c577698cbdb1ea97a0d3d56c33c60be0"
                       "000000000000000000000000000000000000000000000008ac7230489e7fffb",
            .instruction_type = INS_UP,
            .substate_type = SUBSTATE_TYPE_TOKENS,
        },
        {
            .ins_len = 69,
            .ins_hex = "0103010402b8777eab54ba8818cb82376a5798c9c7a025c216fb05266e794cd8c5f0dd4d7a0"
                       "000000000000000000000000000000000000000000000000000000000000001",
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
            .ins_hex = "04361a8ec30813bafdf3b547482353080cc6b7cbd8e893496fa141d9915ae180c300000007",
            .instruction_type = INS_DOWN,
            .substate_type = IRRELEVANT,
        },
        {
            .ins_len = 101,
            .ins_hex = "010d02ec11f6184839402b78f5a6fbe3e5eddf41cb999ac9c3ae0cdb324ab01f8e3f200403a"
                       "8791ee326620a8b0d5ba636eb0422122c577698cbdb1ea97a0d3d56c33c60be000000000000"
                       "0000000000000000000000000000000000008ac7230489e80000",
            .instruction_type = INS_UP,
            .substate_type = SUBSTATE_TYPE_PREPARED_UNSTAKE,
        },
        {
            .ins_len = 1,
            .ins_hex = "00",
            .instruction_type = INS_END,
            .substate_type = IRRELEVANT,
        },
    };

    test_vector_t test_vector = (test_vector_t){
        .total_number_of_instructions = 12,
        .expected_instructions = expected_instructions,
        .expected_result = EXPECTED_RESULT_SUCCESS,
        .expected_success =
            {
                .my_public_key_hex =
                    "02b8777eab54ba8818cb82376a5798c9c7a025c216fb05266e794cd8c5f0dd4d7a",
                .expected_tx_fee = "987654321",
                .expected_total_xrd_amount = "20000000000987654312",
                .expected_hash =
                    {
                        // clang-format off
      0x18, 0x59, 0xc7, 0xa1, 0x1b, 0x46, 0xae, 0xfb,
      0x28, 0x86, 0x0f, 0x37, 0xaf, 0xff, 0x4f, 0xcf,
      0x5a, 0xac, 0x2c, 0x4c, 0x99, 0x5a, 0x65, 0x42,
      0x9a, 0x4f, 0x00, 0xf3, 0x3e, 0x42, 0x98, 0xa3
                        // clang-format on
                    },  //         expected hash:
                        //         1859c7a11b46aefb28860f37afff4fcf5aac2c4c995a65429a4f00f33e4298a3
            },
    };

    do_test_parse_tx(test_vector);
}

/**
 * @brief
 *
 * Blob
 *
 0a0001044b95e6aa95cae5010419b986e8913a5c9628647b0ea21d977dc96c4baa4ef2d200000001092100000000000000000000000000000000000000000000000000000000000000fade01030104034ca24c2b7000f439ca21cbb11b044d48f90c987b2aee6608a2570a466612dae20000000000000000000000000000000000000000000000008ac7230489e7fffc00050000000201030104034ca24c2b7000f439ca21cbb11b044d48f90c987b2aee6608a2570a466612dae20000000000000000000000000000000000000000000000008ac7230489e7fffb010301040345497f80cf2c495286a146178bc2ad1a95232a8fce45856c55d67716cda020b9000000000000000000000000000000000000000000000000000000000000000100050000000501030104034ca24c2b7000f439ca21cbb11b044d48f90c987b2aee6608a2570a466612dae20000000000000000000000000000000000000000000000008ac7230489e7fff9010301040345497f80cf2c495286a146178bc2ad1a95232a8fce45856c55d67716cda020b9000000000000000000000000000000000000000000000000000000000000000200


      Instructions:
      |- HEADER(0, 1)
      |- DOWN(SubstateId { hash:
 0x4b95e6aa95cae5010419b986e8913a5c9628647b0ea21d977dc96c4baa4ef2d2, index: 1 })
      |- SYSCALL(0x00000000000000000000000000000000000000000000000000000000000000fade)
      |- UP(Tokens { rri: 0x01, owner:
 0x04034ca24c2b7000f439ca21cbb11b044d48f90c987b2aee6608a2570a466612dae2, amount: U256 { raw:
 9999999999999999996 } })
      |- END
      |- LDOWN(2)
      |- UP(Tokens { rri: 0x01, owner:
 0x04034ca24c2b7000f439ca21cbb11b044d48f90c987b2aee6608a2570a466612dae2, amount: U256 { raw:
 9999999999999999995 } })
      |- UP(Tokens { rri: 0x01, owner:
 0x040345497f80cf2c495286a146178bc2ad1a95232a8fce45856c55d67716cda020b9, amount: U256 { raw: 1 }
 })
      |- END
      |- LDOWN(5)
      |- UP(Tokens { rri: 0x01, owner:
 0x04034ca24c2b7000f439ca21cbb11b044d48f90c987b2aee6608a2570a466612dae2, amount: U256 { raw:
 9999999999999999993 } })
      |- UP(Tokens { rri: 0x01, owner:
 0x040345497f80cf2c495286a146178bc2ad1a95232a8fce45856c55d67716cda020b9, amount: U256 { raw: 2 }
 })
      |- END


      HEADER(0, 1)
      DOWN(SubstateId { hash:
 0x4b95e6aa95cae5010419b986e8913a5c9628647b0ea21d977dc96c4baa4ef2d2, index: 1 })
 SYSCALL(0x00000000000000000000000000000000000000000000000000000000000000fade) UP(Tokens { rri:
 xrd_rb1qya85pwq, owner: brx1qsp5egjv9dcqpapeegsuhvgmq3x537gvnpaj4mnxpz39wzjxvcfd4csdkqd73,
 amount: 9.0000 }) END LDOWN(2) UP(Tokens { rri: xrd_rb1qya85pwq, owner:
 brx1qsp5egjv9dcqpapeegsuhvgmq3x537gvnpaj4mnxpz39wzjxvcfd4csdkqd73, amount: 9.0000 }) UP(Tokens
 { rri: xrd_rb1qya85pwq, owner:
 brx1qsp52jtlsr8jcj2js6s5v9utc2k349fr928uu3v9d32avackekszpwgwkayzk, amount: 0.0000 }) END
 LDOWN(5) UP(Tokens { rri: xrd_rb1qya85pwq, owner:
 brx1qsp5egjv9dcqpapeegsuhvgmq3x537gvnpaj4mnxpz39wzjxvcfd4csdkqd73, amount: 9.0000 }) UP(Tokens
 { rri: xrd_rb1qya85pwq, owner:
 brx1qsp52jtlsr8jcj2js6s5v9utc2k349fr928uu3v9d32avackekszpwgwkayzk, amount: 0.0000 }) END
 */
static void test_success_transfer_transfer_with_change_transfer_with_change(void **state) {
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
        {
            .ins_len = 5,
            .ins_hex = "0500000002",
            .instruction_type = INS_LDOWN,
            .substate_type = IRRELEVANT,
        },
        {
            .ins_len = 69,
            .ins_hex = "01030104034ca24c2b7000f439ca21cbb11b044d48f90c987b2aee6608a2570a466612dae20"
                       "000000000000000000000000000000000000000000000008ac7230489e7fffb",
            .instruction_type = INS_UP,
            .substate_type = SUBSTATE_TYPE_TOKENS,
        },
        {
            .ins_len = 69,
            .ins_hex = "010301040345497f80cf2c495286a146178bc2ad1a95232a8fce45856c55d67716cda020b90"
                       "000000000000000000000000000000000000000000000000000000000000001",
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
            .ins_hex = "0500000005",
            .instruction_type = INS_LDOWN,
            .substate_type = IRRELEVANT,
        },
        {
            .ins_len = 69,
            .ins_hex = "01030104034ca24c2b7000f439ca21cbb11b044d48f90c987b2aee6608a2570a466612dae20"
                       "000000000000000000000000000000000000000000000008ac7230489e7fff9",
            .instruction_type = INS_UP,
            .substate_type = SUBSTATE_TYPE_TOKENS,
        },
        {
            .ins_len = 69,
            .ins_hex = "010301040345497f80cf2c495286a146178bc2ad1a95232a8fce45856c55d67716cda020b90"
                       "000000000000000000000000000000000000000000000000000000000000002",
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
        .total_number_of_instructions = 13,
        .expected_instructions = expected_instructions,
        .expected_result = EXPECTED_RESULT_SUCCESS,
        .expected_success =
            {
                .my_public_key_hex =
                    "0345497f80cf2c495286a146178bc2ad1a95232a8fce45856c55d67716cda020b9",
                .expected_tx_fee = "64222",
                .expected_total_xrd_amount = "30000000000000064206",
                .expected_hash =
                    {
                        // clang-format off
      0x52, 0xe8, 0x97, 0x42, 0x10, 0xec, 0x91, 0xae,
      0x34, 0x9b, 0x7d, 0x9c, 0x01, 0x6f, 0xcd, 0xfc,
      0x24, 0x08, 0xb3, 0x99, 0x4d, 0xbc, 0xa8, 0x9d,
      0x0a, 0x81, 0xdc, 0x0e, 0x19, 0x75, 0xa1, 0x3b
                        // clang-format on
                    },  //         expected hash:
                        //         52e8974210ec91ae349b7d9c016fcdfc2408b3994dbca89d0a81dc0e1975a13b
            },
    };

    do_test_parse_tx(test_vector);
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

static void test_failure_tx_without_end_instruction(void **state) {
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
        // Should have an END instruction here, but we don't
    };

    uint16_t total_number_of_instructions = 4;

    // clang-format off
    test_vector_t test_vector = (test_vector_t){
        .total_number_of_instructions = total_number_of_instructions,
        .expected_instructions = expected_instructions,
        .expected_result = EXPECTED_FAILURE_REASON_SPECIFIC_INSTRUCTION,
        .expected_failure = {
            .index_of_failing_instruction = total_number_of_instructions - 1, 
            .expected_failure_outcome = {
                .outcome_type = PARSE_PROCESS_INS_LAST_INS_WAS_NOT_INS_END,
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

int main() {
    const struct CMUnitTest success_complex_tx[] = {
        cmocka_unit_test(test_success_transfer_transfer_stake),
        cmocka_unit_test(test_success_transfer_transfer_stake_transfer_with_change),
        cmocka_unit_test(test_success_transfer_transfer_with_change_transfer_stake),
        cmocka_unit_test(test_success_transfer_unstake_transfer_with_change),
        cmocka_unit_test(test_success_transfer_transfer_with_change_unstake),
        cmocka_unit_test(test_success_transfer_transfer_with_change_transfer_with_change),
    };

    const struct CMUnitTest failing_txs[] = {
        cmocka_unit_test(test_failure_missing_header),
        cmocka_unit_test(test_failure_invalid_header_invalid_version),
        cmocka_unit_test(test_failure_invalid_header_invalid_flag),
        cmocka_unit_test(test_failure_no_fee_in_tx),
        cmocka_unit_test(test_failure_invalid_syscall_too_few_bytes),
        cmocka_unit_test(test_failure_tx_without_end_instruction),
        cmocka_unit_test(test_failure_claiming_tx_is_larger_than_sum_of_instruction_byte_count),
        cmocka_unit_test(test_failure_claiming_tx_is_smaller_than_sum_of_instruction_byte_count),

        // Unsupported/Invalid Instructions
        cmocka_unit_test(test_failure_unsupported_instruction_vdown_0x02),
        cmocka_unit_test(test_failure_unsupported_instruction_vdownarg_0x03),
        cmocka_unit_test(test_failure_unsupported_instruction_sig_0x07),
        cmocka_unit_test(test_failure_unsupported_instruction_downall_0x08),

    };

    int status = 0;
    print_message("\n~~~***===<| TEST GROUP: 'success_complex_tx'  |>===***~~~\n");
    status += cmocka_run_group_tests(success_complex_tx, NULL, NULL);
    print_message("\n~~~***===<| TEST GROUP: 'failing_txs'  |>===***~~~\n");
    status += cmocka_run_group_tests(failing_txs, NULL, NULL);
    return status;
}
