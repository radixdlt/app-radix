#pragma once

#include <stdbool.h>   // bool
#include "../state.h"  // transaction_t, re_instruction_t

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
int ui_display_address_from_get_pubkey_cmd(void);

/**
 * Display BIP32 and hash on the device and ask confirmation to sign hash with key at BIP32 path.
 *
 * @return 0 if success, negative integer otherwise.
 *
 */
int ui_display_sign_hash(uint8_t *hash, size_t hash_len);

/**
 * Display BIP32 and pub key of other parth on the device and ask confirmation to sign derive a
 * shared ECDH with pubkey of other party and key at BIP32 path.
 *
 * @return 0 if success, negative integer otherwise.
 *
 */
int ui_display_ecdh(void);

int ui_display_instruction(re_instruction_t *instruction);
int ui_display_tx_summary(transaction_t *transaction, uint8_t *hash, size_t hash_len);