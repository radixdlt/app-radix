#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#include <cmocka.h>

#include "util/sha256.h"
#include "util/debug_print.h"

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

// #include "instruction/instruction.h"
#include "instruction/instruction_type.h"

#include "transaction/transaction.h"
#include "transaction/transaction_parser.h"
#include "transaction/transaction_metadata.h"
#include "transaction/instruction_display_config.h"
#include "transaction/init_transaction_parser_config.h"
#include "transaction/instruction_parser.h"

typedef struct {
    int index;
    buffer_t buffer;

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
        print_error("\n\nHASH:\n");
        size_t i;
        for (i = 0; i < 32; i++) {
            print_error("%02x", out[i]);
        }
        print_error("\n\n");
        // print_message("\n\n\HASH: %64x\n", out);
        // print_array(out, HASH_LEN);
    }
    return true;  // never fails
}

static bool skip_deriving_key(derived_public_key_t *key) {
    // NOOP with key
    return true;
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
 *
 * @param state
 */
static void test_parse_tx(void **state) {
    (void) state;

    const uint16_t total_number_of_instructions = 9;

    // clang-format off
	// Instruction 'HEADER' (#3 bytes)
	static uint8_t ins0[] = {0x0a, 0x00, 0x01};
			
	// Instruction 'DOWN' (#37 bytes)
	static uint8_t ins1[] = { 
		0x04, 0x37, 0x4c, 0x00, 0xef, 0xbe, 0x61, 0xf6,
		0x45, 0xa8, 0xb3, 0x5d, 0x77, 0x46, 0xe1, 0x06,
		0xaf, 0xa7, 0x42, 0x28, 0x77, 0xe5, 0xd6, 0x07,
		0x97, 0x5b, 0x60, 0x18, 0xe0, 0xa1, 0xaa, 0x6b,
		0xf0, 0x00, 0x00, 0x00, 0x04
	};
	
	// Instruction 'SYSCALL' (#35 bytes)
	static uint8_t ins2[] = {
		0x09, 0x21, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x02
	};
	
	// Instruction 'UP' (#69 bytes)
	// Substate type: 'TOKENS'
	static uint8_t ins3[] = {
		0x01, 0x03, 0x01, 0x04, 0x03, 0x77, 0xba, 0xc8,
		0x06, 0x6e, 0x51, 0xcd, 0x0d, 0x6b, 0x32, 0x0c,
		0x33, 0x8d, 0x5a, 0xbb, 0xcd, 0xbc, 0xca, 0x25,
		0x57, 0x2b, 0x6b, 0x3e, 0xee, 0x94, 0x43, 0xea,
		0xfc, 0x92, 0x10, 0x6b, 0xba, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x01, 0x15, 0x8e, 0x46,
		0x09, 0x13, 0xcf, 0xff, 0xfe
	};
	
	// Instruction 'END' (#1 bytes)
	static uint8_t ins4[] = {0x00};
	
	// Instruction 'LDOWN' (#5 bytes)
	static uint8_t ins5[] = {0x05, 0x00, 0x00, 0x00, 0x03};
	
	// Instruction 'UP' (#69 bytes)
	// Substate type: 'TOKENS'
	static uint8_t ins6[] = {
		0x01, 0x03, 0x01, 0x04, 0x03, 0x77, 0xba, 0xc8,
		0x06, 0x6e, 0x51, 0xcd, 0x0d, 0x6b, 0x32, 0x0c,
		0x33, 0x8d, 0x5a, 0xbb, 0xcd, 0xbc, 0xca, 0x25,
		0x57, 0x2b, 0x6b, 0x3e, 0xee, 0x94, 0x43, 0xea,
		0xfc, 0x92, 0x10, 0x6b, 0xba, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x8a, 0xc7, 0x23,
		0x04, 0x89, 0xe7, 0xff, 0xfe
	};
	
	// Instruction 'UP' (#101 bytes)
	// Substate type: 'PREPARED STAKE'
	static uint8_t ins7[] = {
		0x01, 0x04, 0x04, 0x03, 0x77, 0xba, 0xc8, 0x06,
		0x6e, 0x51, 0xcd, 0x0d, 0x6b, 0x32, 0x0c, 0x33,
		0x8d, 0x5a, 0xbb, 0xcd, 0xbc, 0xca, 0x25, 0x57,
		0x2b, 0x6b, 0x3e, 0xee, 0x94, 0x43, 0xea, 0xfc,
		0x92, 0x10, 0x6b, 0xba, 0x02, 0xf1, 0x9b, 0x2d,
		0x09, 0x5a, 0x55, 0x3f, 0x3a, 0x41, 0xda, 0x4a,
		0x8d, 0xc1, 0xf8, 0x45, 0x3d, 0xfb, 0xdc, 0x73,
		0x3c, 0x5a, 0xec, 0xe8, 0xb1, 0x28, 0xb7, 0xd7,
		0x99, 0x9a, 0xe2, 0x47, 0xa5, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x8a, 0xc7, 0x23,
		0x04, 0x89, 0xe8, 0x00, 0x00
	};
	
	// Instruction 'END' (#1 bytes)
	static uint8_t ins8[] = {0x00};
    // clang-format on

    expected_instruction_t expected_instructions[9] = {
        (expected_instruction_t){
            .index = 0,
            .buffer =
                (buffer_t){
                    .offset = 0,
                    .size = 3,
                    .ptr = ins0,
                },
            .instruction_type = INS_HEADER,
            .substate_type = IRRELEVANT,
        },
        (expected_instruction_t){
            .index = 1,
            .buffer =
                (buffer_t){
                    .offset = 0,
                    .size = 37,
                    .ptr = ins1,
                },
            .instruction_type = INS_DOWN,
            .substate_type = IRRELEVANT,
        },
        (expected_instruction_t){
            .index = 2,
            .buffer =
                (buffer_t){
                    .offset = 0,
                    .size = 35,
                    .ptr = ins2,
                },
            .instruction_type = INS_SYSCALL,
            .substate_type = IRRELEVANT,
        },
        (expected_instruction_t){
            .index = 3,
            .buffer =
                (buffer_t){
                    .offset = 0,
                    .size = 69,
                    .ptr = ins3,
                },
            .instruction_type = INS_UP,
            .substate_type = SUBSTATE_TYPE_TOKENS,
        },
        (expected_instruction_t){
            .index = 4,
            .buffer =
                (buffer_t){
                    .offset = 0,
                    .size = 1,
                    .ptr = ins4,
                },
            .instruction_type = INS_END,
            .substate_type = IRRELEVANT,
        },
        (expected_instruction_t){
            .index = 5,
            .buffer =
                (buffer_t){
                    .offset = 0,
                    .size = 5,
                    .ptr = ins5,
                },
            .instruction_type = INS_LDOWN,
            .substate_type = IRRELEVANT,
        },
        (expected_instruction_t){
            .index = 6,
            .buffer =
                (buffer_t){
                    .offset = 0,
                    .size = 69,
                    .ptr = ins6,
                },
            .instruction_type = INS_UP,
            .substate_type = SUBSTATE_TYPE_TOKENS,
        },
        (expected_instruction_t){
            .index = 7,
            .buffer =
                (buffer_t){
                    .offset = 0,
                    .size = 101,
                    .ptr = ins7,
                },
            .instruction_type = INS_UP,
            .substate_type = SUBSTATE_TYPE_PREPARED_STAKE,
        },
        (expected_instruction_t){
            .index = 8,
            .buffer =
                (buffer_t){
                    .offset = 0,
                    .size = 1,
                    .ptr = ins8,
                },
            .instruction_type = INS_END,
            .substate_type = IRRELEVANT,
        },
    };

    const uint32_t tx_byte_count = 321;

    transaction_parser_t tx_parser;

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

    char output[UINT256_DEC_STRING_MAX_LENGTH] = {0};
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
                                                                      &skip_deriving_key,
                                                                      &update_sha256_hasher_hash,
                                                                      &init_sha256_hasher,
                                                                      &tx_parser_config,
                                                                      &init_tx_parser_outcome);

    assert_true(init_tx_parser_successful);

    for (int instruction_index = 0; instruction_index < total_number_of_instructions;
         instruction_index++) {
        expected_instruction_t *expected_instruction = &expected_instructions[instruction_index];
        buffer_t *buf = &expected_instruction->buffer;
        assert_int_equal(buf->offset, 0);

        parse_and_process_instruction_outcome_t outcome;
        const bool parse_in_successful =
            parse_and_process_instruction_from_buffer(buf, &tx_parser, &outcome);

        dbg_print_parse_process_instruction_outcome(&outcome);

        assert_true(parse_in_successful);

        if (instruction_index == total_number_of_instructions - 1) {
            // Last
            assert_int_equal(outcome.outcome_type,
                             PARSE_PROCESS_INS_SUCCESS_FINISHED_PARSING_WHOLE_TRANSACTION);
        } else {
            assert_int_equal(outcome.outcome_type, PARSE_PROCESS_INS_SUCCESS_FINISHED_PARSING_INS);

            re_instruction_type_e parsed_ins_type =
                tx_parser.instruction_parser.instruction.ins_type;

            assert_int_equal(parsed_ins_type, expected_instruction->instruction_type);
            if (parsed_ins_type == INS_UP) {
                re_substate_type_e parsed_substate_type =
                    tx_parser.instruction_parser.instruction.ins_up.substate.type;
                assert_int_equal(parsed_substate_type, expected_instruction->substate_type);
            }
        }
    }

    transaction_t *transaction = &tx_parser.transaction;
    assert_true(transaction->have_asserted_no_mint_or_burn);

    // clang-format off
    // Expected hash sha256 TWICE: 83f4544ff1fbabc7be39c6f531c3f37fc50e0a0b653afdb22cc9f8e8aa461fc9
    uint8_t expected_hash_twice[32] = {
    	0x83, 0xf4, 0x54, 0x4f, 0xf1, 0xfb, 0xab, 0xc7,
    	0xbe, 0x39, 0xc6, 0xf5, 0x31, 0xc3, 0xf3, 0x7f,
    	0xc5, 0x0e, 0x0a, 0x0b, 0x65, 0x3a, 0xfd, 0xb2,
    	0x2c, 0xc9, 0xf8, 0xe8, 0xaa, 0x46, 0x1f, 0xc9
    };
    // clang-format on

    assert_memory_equal(tx_parser.signing.hasher.hash, expected_hash_twice, HASH_LEN);

    memset(output, 0, sizeof(output));
    const bool format_fee_successfull =
        to_string_uint256(&transaction->tx_fee, output, sizeof(output));
    assert_true(format_fee_successfull);
    assert_string_equal(output, "2");  // tx fee

    memset(output, 0, sizeof(output));
    size_t total_amount_len;
    const bool format_total_cost_successfull =
        to_string_uint256_get_len(&transaction->total_xrd_amount_incl_fee,
                                  output,
                                  sizeof(output),
                                  &total_amount_len);

    assert_true(format_total_cost_successfull);

    // Ugh... `assert_string_equal` was unstable, 1/3 it fails, and the resulting string was way to
    // long, this ugly manual fix copies over just the relevant bits.
    char output2[UINT256_DEC_STRING_MAX_LENGTH] = {0};
    memset(output2, 0, sizeof(output2));
    memmove(output2, output, total_amount_len);
    assert_string_equal(output2, "29999999999999999998");  // total_xrd_amount_incl_fee
}

int main() {
    const struct CMUnitTest tests[] = {cmocka_unit_test(test_parse_tx)};

    return cmocka_run_group_tests(tests, NULL, NULL);
}
