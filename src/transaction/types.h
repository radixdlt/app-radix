#pragma once

#include <stddef.h>              // size_t
#include <stdint.h>              // uint*_t
#include "../account_address.h"  // ACCOUNT_ADDRESS_LEN

#define MAX_TX_LEN  510
#define MAX_MSG_LEN 256

typedef enum {
    PARSING_OK = 1,
    NONCE_PARSING_ERROR = -1,
    TO_PARSING_ERROR = -2,
    VALUE_PARSING_ERROR = -3,
    MEMO_LENGTH_ERROR = -4,
    MEMO_PARSING_ERROR = -5,
    MEMO_ENCODING_ERROR = -6,
    WRONG_LENGTH_ERROR = -7
} parser_status_e;

typedef struct {
    uint64_t nonce;        /// nonce (8 bytes)
    uint64_t value;        /// amount value (8 bytes)
    uint8_t *to;           /// pointer to address (20 bytes)
    uint8_t *message;      /// message (variable length)
    uint64_t message_len;  /// length of message (8 bytes)
} transaction_t;
