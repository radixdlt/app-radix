cmake_minimum_required(VERSION 3.10)

if(${CMAKE_VERSION} VERSION_LESS 3.10)
    cmake_policy(VERSION ${CMAKE_MAJOR_VERSION}.${CMAKE_MINOR_VERSION})
endif()

# project information
project(unit_tests
        VERSION 0.1
	      DESCRIPTION "Unit tests for Ledger Nano application"
        LANGUAGES C)


# guard against bad build-type strings
if (NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE "Debug")
endif()

include(CTest)
ENABLE_TESTING()

# specify C standard
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED True)
set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -Wall -pedantic -g -O0 --coverage")

set(GCC_COVERAGE_LINK_FLAGS "--coverage -lgcov")
set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} ${GCC_COVERAGE_LINK_FLAGS}")
set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} ${GCC_COVERAGE_LINK_FLAGS}")

# guard against in-source builds
if(${CMAKE_SOURCE_DIR} STREQUAL ${CMAKE_BINARY_DIR})
  message(FATAL_ERROR "In-source builds not allowed. Please make a new directory (called a build directory) and run CMake from there. You may need to remove CMakeCache.txt. ")
endif()

add_compile_definitions(TEST)

include_directories(../src)

add_executable(test_tx_parser test_tx_parser.c)

add_library(sha256 SHARED util/sha256.c)
add_library(debug_print SHARED util/debug_print.c)
add_library(hex_to_bin SHARED util/hex_to_bin.c)

add_library(read SHARED ../src/common/read.c)
add_library(format SHARED ../src/common/format.c)
add_library(bech32_encode SHARED ../src/common/bech32_encode.c)

add_library(public_key SHARED ../src/types/public_key.c)
add_library(buffer SHARED ../src/types/buffer.c)
add_library(bip32_path SHARED ../src/types/bip32_path.c)
add_library(hasher SHARED ../src/types/hasher.c)

# target_link_libraries(hasher PUBLIC buffer)

add_library(uint256 SHARED ../src/types/uint256.c)
#
# We MUST explicitly state that `uint256.c` depends on `buffer.c` (method: `buffer_move_fill_target`)
target_link_libraries(uint256 PUBLIC buffer)

add_library(re_bytes SHARED ../src/types/re_bytes.c)
add_library(re_address_type SHARED ../src/types/re_address_type.c)
add_library(re_address SHARED ../src/types/re_address.c)

# We MUST explicitly state that `re_address.c` depends on `re_address_type.c` (methods: `is_re_address_type_supported`, `is_re_address_type_known`)
target_link_libraries(re_address PUBLIC re_address_type)

# We MUST explicitly state that `re_address.c` depends on `bech32_encode.c` (methods: `bech32_encode`, `convert_bits`)
target_link_libraries(re_address PUBLIC bech32_encode)

add_library(derived_public_key SHARED ../src/types/derived_public_key.c)

add_library(tokens SHARED ../src/instruction/substate/tokens.c)
add_library(prepared_stake SHARED ../src/instruction/substate/prepared_stake.c)
add_library(stake_ownership SHARED ../src/instruction/substate/stake_ownership.c)
add_library(prepared_unstake SHARED ../src/instruction/substate/prepared_unstake.c)
add_library(validator_allow_delegation_flag SHARED ../src/instruction/substate/validator_allow_delegation_flag.c)
add_library(validator_owner_copy SHARED ../src/instruction/substate/validator_owner_copy.c)

# We MUST explicitly state that `prepared_unstake.c` depends on `re_address.c` (method: `parse_re_address`)
target_link_libraries(prepared_unstake PUBLIC re_address)

add_library(substate_type SHARED ../src/instruction/substate/substate_type.c)
add_library(substate SHARED ../src/instruction/substate/substate.c)

# We MUST explicitly state that `substate.c` depends on `prepared_unstake.c` (methods: `parse_prepared_unstake`, `status_word_for_failed_to_parse_prepared_unstake`)
target_link_libraries(substate PUBLIC prepared_unstake)

# We MUST explicitly state that `substate.c` depends on `prepared_stake.c` (methods: `parse_prepared_stake`, `status_word_for_failed_to_parse_prepared_stake`)
target_link_libraries(substate PUBLIC prepared_stake)

# We MUST explicitly state that `substate.c` depends on `tokens.c` (methods: `parse_tokens`, `status_word_for_failed_to_parse_tokens`)
target_link_libraries(substate PUBLIC tokens)

# We MUST explicitly state that `substate.c` depends on `stake_ownership.c` (methods: `parse_stake_ownership`, `status_word_for_failed_to_parse_stake_ownership`)
target_link_libraries(substate PUBLIC stake_ownership)

# We MUST explicitly state that `substate.c` depends on `validator_allow_delegation_flag.c` (methods: `parse_validator_allow_delegation_flag`...)
target_link_libraries(substate PUBLIC validator_allow_delegation_flag)
# We MUST explicitly state that `substate.c` depends on `validator_owner_copy.c` (methods: `parse_validator_owner_copy`...)
target_link_libraries(substate PUBLIC validator_owner_copy)


# We MUST explicitly state that `substate.c` depends on `substate_type.c` (methods: `is_re_substate_type_known`, `is_re_substate_type_supported`)
target_link_libraries(substate PUBLIC substate_type)




add_library(substate_id SHARED ../src/instruction/substate/substate_id.c)

add_library(instruction SHARED ../src/instruction/instruction.c)
# We MUST explicitly state that `instruction.c` depends on `public_key.c` (method: `public_key_equals`)
target_link_libraries(instruction PUBLIC public_key)
# We MUST explicitly state that `instruction.c` depends on `re_bytes.c` (method: `parse_re_bytes`)
target_link_libraries(instruction PUBLIC re_bytes)
# We MUST explicitly state that `instruction.c` depends on `substate.c` (method: `parse_substate`)
target_link_libraries(instruction PUBLIC substate)
# We MUST explicitly state that `instruction.c` depends on `substate_id.c (method: `parse_substate_id`)`
target_link_libraries(instruction PUBLIC substate_id)

add_library(instruction_type SHARED ../src/instruction/instruction_type.c)
add_library(transaction SHARED ../src/transaction/transaction.c)

# We MUST explicitly state that `transaction.c` depends on `uint256.c (method: `gt256`)`
target_link_libraries(transaction PUBLIC uint256)

add_library(transaction_parser SHARED ../src/transaction/transaction_parser.c)

# We MUST explicitly state that `transaction_parser.c` depends on `uint256.c` (method: `readu256BE`)
target_link_libraries(transaction_parser PUBLIC uint256)

# We MUST explicitly state that `transaction_parser.c` depends on `hasher.c` (method: `init_hasher`, `update_hash_twice`)
target_link_libraries(transaction_parser PUBLIC hasher)

# We MUST explicitly state that `transaction_parser.c` depends on `transaction.c` (method: `is_tx_fee_set`)
target_link_libraries(transaction_parser PUBLIC transaction)

add_library(transaction_metadata SHARED ../src/transaction/transaction_metadata.c)
add_library(instruction_display_config SHARED ../src/transaction/instruction_display_config.c)
add_library(init_transaction_parser_config SHARED ../src/transaction/init_transaction_parser_config.c)
add_library(instruction_parser SHARED ../src/transaction/instruction_parser.c)

target_link_libraries(test_tx_parser PUBLIC
                      cmocka
                      gcov
                      sha256
                      debug_print
                      hex_to_bin
                      hasher
                      public_key
                      buffer
                      re_bytes
                      re_address
                      derived_public_key
                      bip32_path
                      read
                      uint256
                      format
                      substate_type
                      substate
                      substate_id
                      tokens
                      prepared_stake
                      prepared_unstake
                      stake_ownership
                      validator_allow_delegation_flag
                      validator_owner_copy
                      transaction
                      transaction_parser
                      transaction_metadata
                      instruction
                      instruction_type
                      instruction_parser
                      instruction_display_config
                      init_transaction_parser_config
                      )

add_test(test_tx_parser test_tx_parser)
