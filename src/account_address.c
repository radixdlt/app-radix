#include "account_address.h"
#include "common/abstract_address.h"  // abstract_addr_from_bytes
#include "macros.h"                   // ASSERT
#include "constants.h"                // PUBLIC_KEY_COMPRESSED_LEN
#include <string.h>                   // memset

bool account_address_from_pubkey(const uint8_t raw_public_key[static PUBLIC_KEY_COMPRESSED_LEN],
                                 char *out,
                                 size_t *out_len) {
    ASSERT(*out_len >= ACCOUNT_ADDRESS_LEN, "Account address must fit in `out` string.");

    uint8_t data[PUBLIC_KEY_COMPRESSED_LEN + ACCOUNT_ADDRESS_VERSION_DATA_LENGTH];

    memset(data, ACCOUNT_ADDRESS_VERSION_BYTE, ACCOUNT_ADDRESS_VERSION_DATA_LENGTH);
    memmove(data + ACCOUNT_ADDRESS_VERSION_DATA_LENGTH, raw_public_key, PUBLIC_KEY_COMPRESSED_LEN);

    if (!abstract_addr_from_bytes(ACCOUNT_ADDRESS_HRP_BETANET,  // ACCOUNT_ADDRESS_HRP_MAINNET
                                  ACCOUNT_ADDRESS_HRP_LENGTH,
                                  data,
                                  sizeof(data),
                                  out,
                                  out_len)) {
        PRINTF("Bech32 encoding of account address failed.\n");
        return false;
    }

    return true;
}
