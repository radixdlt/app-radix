#pragma once

#include <stdbool.h>  // bool

/**
 * Action for public key validation and export.
 *
 * @param[in] choice
 *   User choice (either approved or rejectd).
 *
 */
void ui_action_validate_pubkey(bool choice);

/**
 * Action for signature information validation.
 * From sign hash flow.
 *
 * @param[in] choice
 *   User choice (either approved or rejectd).
 *
 */
void ui_action_validate_sign_hash(bool choice);

/**
 * Action for signature information validation.
 * From sign tx flow. Differs a bit from sign
 * hash flow, because we should respond with
 * calculated hash back to host machine.
 *
 * @param[in] choice
 *   User choice (either approved or rejectd).
 *
 */
void ui_action_validate_sign_tx(bool choice);

/**
 * Action for shared key validation and export.
 *
 * @param[in] choice
 *   User choice (either approved or rejectd).
 *
 */
void ui_action_validate_sharedkey(bool choice);