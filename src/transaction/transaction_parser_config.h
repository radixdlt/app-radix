#pragma once

#include "transaction_metadata.h"
#include "parsed_instruction_display_config.h"

typedef struct {
    transaction_metadata_t transaction_metadata;
    parsed_instruction_display_config_t parsed_instruction_display_config;
} transaction_parser_config_t;