#pragma once

#include <stdbool.h>

typedef struct {
    bool display_substate_contents;  /// If a parsed UP:ed substate should be display, convenient to
                                     /// use 'false' for testing.
    bool display_tx_summary;  /// If a summary of the contents of a transaction should be displayed,
                              /// convenient to use 'false' for testing.
} instruction_display_config_t;