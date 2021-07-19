#include "transaction.h"

bool is_tx_fee_set(const transaction_t *transaction) {
    return is_uint256_greater_than_zero(&transaction->tx_fee);
}