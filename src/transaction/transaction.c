#include "transaction.h"

bool is_tx_fee_set(transaction_t *transaction) {
    uint256_t zero;
    clear256(&zero);
    return gt256(&transaction->tx_fee, &zero);
}