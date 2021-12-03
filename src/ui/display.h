#pragma once

#include <stdbool.h>   // bool
#include "../state.h"  // transaction_t, re_instruction_t, derived_public_key_t
#include "../handler/ecdh.h"

#define DISPLAYED_AMOUNT_LEN              \
    (UINT256_DEC_STRING_MAX_LENGTH + 12 + \
     2)  // +12 for length of "StakeUnits: ", +1 for \0, +1 for '.'
#define DISPLAYED_HASH_LEN \
    (HASH_LEN * 2 + 1)  // x2 factor for 2chars per bytes in hex and +1 for Null terminator
#define DISPLAYED_ACCOUNT_ADDR_LEN (ACCOUNT_ADDRESS_LEN + 1)  // +1 for Null terminator
#define DISPLAYED_RRI_LEN          DISPLAYED_ACCOUNT_ADDR_LEN

/**
 * Callback to reuse action with approve/reject in step FLOW.
 */
typedef void (*action_validate_cb)(user_accepted_t);

/**
 * Display address on the device and ask confirmation to export.
 *
 * @return 0 if success, negative integer otherwise.
 *
 */

int ui_display_address_from_get_pubkey_cmd(derived_public_key_t *my_derived_public_key,
                                           bool address_verification_only);

/**
 * Display BIP32 and hash on the device and ask confirmation to sign hash with key at BIP32
 * path.
 *
 * @return 0 if success, negative integer otherwise.
 *
 */
int ui_display_sign_hash(bip32_path_t *bip32_path, uint8_t *hash, size_t hash_len);

/**
 * Display BIP32 and pub key of other party on the device and ask confirmation to sign derive a
 * shared ECDH with pubkey of other party and key at BIP32 path.
 *
 * @return 0 if success, negative integer otherwise.
 *
 */
int ui_display_ecdh(derived_public_key_t *my_derived_public_key,
                    re_address_t *other_party_address,
                    display_state_t display);

int ui_display_instruction(re_instruction_t *instruction);
int ui_display_tx_summary(transaction_t *transaction);