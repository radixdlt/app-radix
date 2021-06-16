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

add_library(bip32 SHARED ../src/types/bip32_path.c)
add_library(format SHARED ../src/common/format.c)

add_library(transaction ../src/transaction/transaction.c)
add_library(transaction_parser ../src/transaction/transaction_parser.c)
add_library(transaction_metadata ../src/transaction/transaction_metadata.c)
add_library(instruction_display_config ../src/transaction/instruction_display_config.c)
add_library(init_transaction_parser_config ../src/transaction/init_transaction_parser_config.c)


add_library(instruction_type ../src/instruction/instruction_type.c)
add_library(substate_type ../src/instruction/substate/substate_type.c)


target_link_libraries(test_tx_parser PUBLIC
                      cmocka
                      gcov
                      transaction
                      transaction_parser
                      transaction_metadata
                      instruction_type
                      instruction_display_config
                      init_transaction_parser_config
                      substate_type
                      bip32
                      format
                      )

add_test(test_tx_parser test_tx_parser)
