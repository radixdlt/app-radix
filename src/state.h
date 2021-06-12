#pragma once

#include <stddef.h>  // size_t
#include <stdint.h>  // uint*_t

#include "constants.h"
#include "instruction/instruction.h"
#include "common/bip32.h"
#include "os.h"
#include "common/public_key.h"
#include "common/bech32_encode.h"

/**
 * Enumeration for the status of IO.
 */
typedef enum {
    READY,     /// ready for new event
    RECEIVED,  /// data received
    WAITING    /// waiting
} io_state_e;

/**
 * Enumeration with expected INS of APDU commands.
 */
typedef enum {
    GET_VERSION = 0x03,     /// version of the application
    GET_APP_NAME = 0x04,    /// name of the application
    GET_PUBLIC_KEY = 0x05,  /// public key of corresponding BIP32 path
    SIGN_TX = 0x06,         /// sign transaction with BIP32 path
    SIGN_HASH = 0x07,       /// sign hash with BIP32 path
    ECDH = 0x08             /// ECDH with BIP32 path and provided public key of other party
} command_e;

/**
 * Structure with fields of APDU command.
 */
typedef struct {
    uint8_t cla;    /// Instruction class
    command_e ins;  /// Instruction code
    uint8_t p1;     /// Instruction parameter 1
    uint8_t p2;     /// Instruction parameter 2
    uint8_t lc;     /// Lenght of command data
    uint8_t *data;  /// Command data
} command_t;

/**
 * Enumeration with tx state.
 */
typedef enum {
    STATE_NONE,
    STATE_PARSED,
    STATE_APPROVED,
} state_e;

typedef enum {
    STATE_PARSE_INS_READY_TO_PARSE = 1,
    STATE_PARSE_INS_PARSED_INSTRUCTION,
    STATE_PARSE_INS_NEEDS_APPROVAL,
    STATE_PARSE_INS_APPROVED,
    STATE_PARSE_INS_FINISHED_PARSING_ALL_INS,
} parse_tx_ins_state_e;

void G_update_parse_tx_ins_state(parse_tx_ins_state_e new_state);
void G_parse_tx_state_ready_to_parse(void);
void G_parse_tx_state_did_parse_new(void);
void G_parse_tx_state_ins_needs_approval(void);
void G_parse_tx_state_did_approve_ins(void);
void G_parse_tx_state_finished_parsing_all(void);

/**
 * Enumeration with user request type.
 */
typedef enum {
    CONFIRM_ADDRESS,      /// confirm address derived from public key
    CONFIRM_ECDH,         /// confirm ECDH key information
    CONFIRM_HASH,         /// confirm hash information
    CONFIRM_TRANSACTION,  /// confirm transaction information
} request_type_e;

/**
 * Structure for public key context information.
 */
typedef struct {
    uint8_t raw_uncompressed_public_key[PUBLIC_KEY_UNCOMPRESSEED_LEN];  /// x-coordinate (32),
                                                                        /// y-coodinate (32)
    re_address_t my_address;
    uint8_t chain_code[CHAIN_CODE_LEN];  /// for public key derivation
} get_public_key_ctx_t;

/**
 * Structure for ECDH key exchange context information.
 */
typedef struct {
    cx_ecfp_public_key_t other_party_public_key;
    re_address_t other_party_address;
    uint8_t shared_pubkey_point[PUBLIC_KEY_POINT_LEN];
} ecdh_ctx_t;

/**
 * Structure for transaction information context.
 */
typedef struct {
    parse_tx_ins_state_e parse_ins_state;
    bool display_substate_contents;  /// If a parsed UP:ed substate should be display, convenient to
                                     /// use 'false' for testing.
    bool display_tx_summary;  /// If a summary of the contents of a transaction should be displayed,
                              /// convenient to use 'false' for testing.

    char hrp_non_native_token[MAX_BECH32_HRP_PART_LEN];
    uint8_t hrp_non_native_token_len;

    uint32_t tx_byte_count;            /// Number of bytes in the while transaction to receive.
    uint32_t tx_bytes_received_count;  /// Number of tx bytes received

    uint16_t total_number_of_instructions;     /// Number of Radix Engine instructions to receive.
    uint16_t number_of_instructions_received;  /// Number of Radix Engine instructions that has been
                                               /// received.

    cx_sha256_t hasher;
    uint256_t tx_fee;  /// The tee of this transaction, measured in XRD.
    uint256_t total_xrd_amount_incl_fee;
    bool have_asserted_no_mint_or_burn;

    public_key_t my_public_key;  /// The public key corresponding to the provided BIP32 path, used
                                 /// to determine if some tokens are "change back to myself"

    re_instruction_t instruction;  /// lasest parsed Radix Engine instruction
} sign_transaction_ctx_t;

typedef struct {
    uint8_t m_hash[HASH_LEN];            /// message hash digest
    uint8_t signature[MAX_DER_SIG_LEN];  /// transaction signature encoded in DER
    uint8_t signature_len;               /// length of transaction signature
    uint8_t v;                           /// parity of y-coordinate of R in ECDSA signature
} signature_ctx_t;

/**
 * Structure for global context.
 */
typedef struct {
    state_e state;  /// state of the context
    union {
        get_public_key_ctx_t pk_info;    /// public key context
        ecdh_ctx_t ecdh_info;            /// ECDH key exchange context
        sign_transaction_ctx_t tx_info;  /// sign transaction context
    };
    request_type_e req_type;              /// user request
    uint32_t bip32_path[MAX_BIP32_PATH];  /// BIP32 path
    uint8_t bip32_path_len;               /// lenght of BIP32 path
    signature_ctx_t
        sig_info;  /// A signature produces by this app, etiher during SIGN_HASH or SIGN_TX flow.
} global_ctx_t;
