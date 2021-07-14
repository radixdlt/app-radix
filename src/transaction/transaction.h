#pragma once

#include <stdbool.h>
#include "../types/uint256.h"

typedef struct {
    uint256_t tx_fee;  /// The fee of this transaction, measured in XRD.
    uint256_t total_xrd_amount_incl_fee;

    bool have_asserted_no_mint_or_burn;

} transaction_t;

bool is_tx_fee_set(transaction_t *transaction);