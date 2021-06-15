#pragma once

#include <stdint.h>
#include <stdbool.h>
#include "../types/buffer.h"

#define MAX_BYTES_LEN 255

typedef struct {
    uint8_t length;
    uint8_t data[MAX_BYTES_LEN];
} re_bytes_t;

typedef enum {
    PARSE_BYTES_OK = 0,
    PARSE_BYTES_FAILED_TO_PARSE_LENGTH = 1,
    PARSE_BYTES_FAIL_WRONG_LENGTH = 2,
} parse_bytes_outcome_e;

bool parse_re_bytes(buffer_t *buffer, parse_bytes_outcome_e *outcome, re_bytes_t *bytes);

uint16_t status_word_for_failed_to_parse_bytes(parse_bytes_outcome_e outcome);
void print_parse_bytes_outcome(parse_bytes_outcome_e outcome);
