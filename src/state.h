#pragma once

#include <stddef.h>  // size_t
#include <stdint.h>  // uint*_t

#include "transaction/transaction_parser.h"

typedef bool user_accepted_t;

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
    uint8_t* data;  /// Command data
} command_t;

/**
 * Enumeration with tx state.
 */
typedef enum {
    STATE_NONE,
    STATE_PARSED,
    STATE_APPROVED,
} state_e;

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

typedef uint16_t status_word_t;

/**
 * Structure for public key context information.
 */
typedef struct {
    uint8_t raw_uncompressed_public_key[PUBLIC_KEY_UNCOMPRESSEED_LEN];  /// x-coordinate (32),
                                                                        /// y-coodinate (32)
    derived_public_key_t my_derived_public_key;
    uint8_t chain_code[CHAIN_CODE_LEN];  /// for public key derivation
} get_public_key_ctx_t;

/**
 * Structure for ECDH key exchange context information.
 */
typedef struct {
    derived_public_key_t my_derived_public_key;  /// Public key and BIP32 path used to perform ECDH.
    cx_ecfp_public_key_t other_party_public_key;
    re_address_t other_party_address;
    uint8_t shared_pubkey_point[PUBLIC_KEY_POINT_LEN];
} ecdh_ctx_t;

/**
 * Structure for transaction information context.
 */
typedef struct {
    transaction_parser_t transaction_parser;
} sign_transaction_ctx_t;

/**
 * Structure for sign hash context.
 */
typedef struct {
    signing_t signing;
} sign_hash_ctx_t;

/**
 * Structure for global context.
 */
typedef struct {
    state_e state;  /// state of the context
    union {
        get_public_key_ctx_t pk_info;         /// public key context
        ecdh_ctx_t ecdh_info;                 /// ECDH key exchange context
        sign_transaction_ctx_t sign_tx_info;  /// sign transaction context
        sign_hash_ctx_t sign_hash_info;       /// sign transaction context
    };
    request_type_e req_type;  /// user request
} global_ctx_t;
