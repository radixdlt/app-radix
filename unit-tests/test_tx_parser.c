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
    uint16_t total_number_of_instructions;
    expected_instruction_t *expected_instructions;
    char *expected_tx_fee;
    char *expected_total_xrd_amount;
    uint8_t expected_hash[HASH_LEN];
    char *my_public_key_hex;  // used to check token transfer change
} test_vector_t;

static void do_test_parse_tx(test_vector_t test_vector) {
    uint16_t total_number_of_instructions = test_vector.total_number_of_instructions;
    expected_instruction_t *expected_instructions = test_vector.expected_instructions;
    char *expected_tx_fee = test_vector.expected_tx_fee;
    char *expected_total_xrd_amount = test_vector.expected_total_xrd_amount;
    uint8_t *expected_hash = test_vector.expected_hash;

    hex_to_bin(test_vector.my_public_key_hex, pub_key_bytes, PUBLIC_KEY_COMPRESSED_LEN);

    size_t i;
    uint32_t tx_byte_count = 0;
    for (i = 0; i < total_number_of_instructions; i++) {
        expected_instruction_t *expected_instruction = &expected_instructions[i];
        size_t instruction_size = expected_instruction->ins_len;
        tx_byte_count += instruction_size;
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
    bool parse_in_successful = false;
    re_instruction_type_e parsed_ins_type;

    for (i = 0; i < total_number_of_instructions; i++) {
        expected_instruction = expected_instructions[i];
        size_t instruction_size = expected_instruction.ins_len;
        buf.offset = 0;
        buf.size = instruction_size;
        hex_to_bin(expected_instruction.ins_hex, bytes255, instruction_size);
        buf.ptr = bytes255;

        parse_in_successful = parse_and_process_instruction_from_buffer(&buf, &tx_parser, &outcome);

        dbg_print_parse_process_instruction_outcome(&outcome);

        assert_true(parse_in_successful);

        if (i == total_number_of_instructions - 1) {
            // Last
            assert_int_equal(outcome.outcome_type,
                             PARSE_PROCESS_INS_SUCCESS_FINISHED_PARSING_WHOLE_TRANSACTION);
        } else {
            assert_int_equal(outcome.outcome_type, PARSE_PROCESS_INS_SUCCESS_FINISHED_PARSING_INS);

            parsed_ins_type = tx_parser.instruction_parser.instruction.ins_type;

            assert_int_equal(parsed_ins_type, expected_instruction.instruction_type);
            if (parsed_ins_type == INS_UP) {
                re_substate_type_e parsed_substate_type =
                    tx_parser.instruction_parser.instruction.ins_up.substate.type;
                assert_int_equal(parsed_substate_type, expected_instruction.substate_type);
            }
        }
    }

    transaction_t transaction = tx_parser.transaction;

    // Must not allow burning/minting
    assert_true(transaction.have_asserted_no_mint_or_burn);

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
static void test_tx_2_transfer_1_stake(void **state) {
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
        .my_public_key_hex = "026d5e07cfde5df84b5ef884b629d28d15b0f6c66be229680699767cd57c618288",

    };

    do_test_parse_tx(test_vector);
}

/**
 * @brief
 * BLOB
 * 0a0001045d375643dded796e8d3526dcae7a068c642e35fb9931688f56ea20b56289330f0000000309210000000000000000000000000000000000000000000000000000000000deadbeef0103010402ed0eeaf54a79df88f12f251f22b88df00afaad43497f448620353a94e5c2e155000000000000000000000000000000000000000000000001158e460913cffffe0005000000020103010402ed0eeaf54a79df88f12f251f22b88df00afaad43497f448620353a94e5c2e1550000000000000000000000000000000000000000000000008ac7230489e7fffe01040402ed0eeaf54a79df88f12f251f22b88df00afaad43497f448620353a94e5c2e15502fd72e14bae5305db65f51d723e0a68a54a49dc85d0875b44d3cf1e80413de8870000000000000000000000000000000000000000000000008ac7230489e800000005000000050103010402ed0eeaf54a79df88f12f251f22b88df00afaad43497f448620353a94e5c2e1550000000000000000000000000000000000000000000000008ac7230489e7fffd01030104036b062b0044f412f30a973947e5e986629669d055b78fcfbb68a63211462ed0f7000000000000000000000000000000000000000000000000000000000000000100

      Instructions:
      |- HEADER(0, 1)
      |- DOWN(SubstateId { hash: 0x5d375643dded796e8d3526dcae7a068c642e35fb9931688f56ea20b56289330f,
 index: 3 })
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
 0x04036b062b0044f412f30a973947e5e986629669d055b78fcfbb68a63211462ed0f7, amount: U256 { raw: 1 } })
      |- END


    More human readable

      HEADER(0, 1)
      DOWN(SubstateId { hash: 0x5d375643dded796e8d3526dcae7a068c642e35fb9931688f56ea20b56289330f,
 index: 3 })
      SYSCALL(0x0000000000000000000000000000000000000000000000000000000000deadbeef)
      UP(Tokens { rri: xrd_rb1qya85pwq, owner:
 brx1qspw6rh27498nhug7yhj28ezhzxlqzh644p5jl6yscsr2w55uhpwz4gcpqecd, amount: 19.0000 })
      END
      LDOWN(2)
      UP(Tokens { rri: xrd_rb1qya85pwq, owner:
 brx1qspw6rh27498nhug7yhj28ezhzxlqzh644p5jl6yscsr2w55uhpwz4gcpqecd, amount: 9.0000 })
      UP(PreparedStake { owner: brx1qspw6rh27498nhug7yhj28ezhzxlqzh644p5jl6yscsr2w55uhpwz4gcpqecd,
 delegate: vb1qt7h9c2t4efstkm975why0s2dzj55jwushggwk6y6083aqzp8h5gwr7x4gz, amount: 10.0000 })
      END
      LDOWN(5)
      UP(Tokens { rri: xrd_rb1qya85pwq, owner:
 brx1qspw6rh27498nhug7yhj28ezhzxlqzh644p5jl6yscsr2w55uhpwz4gcpqecd, amount: 9.0000 })
      UP(Tokens { rri: xrd_rb1qya85pwq, owner:
 brx1qspkkp3tqpz0gyhnp2tnj3l9axrx99nf6p2m0r70hd52vvs3gchdpacsadyal, amount: 0.0000 })
      END
 *
 * @param state
 */
static void test_Fee_Stake_Transfer(void **state) {
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
        .my_public_key_hex = "036b062b0044f412f30a973947e5e986629669d055b78fcfbb68a63211462ed0f7",
    };

    do_test_parse_tx(test_vector);
}

int main() {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_tx_2_transfer_1_stake),
        cmocka_unit_test(test_Fee_Stake_Transfer),

    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
