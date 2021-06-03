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
 *
 * @param[in] choice
 *   User choice (either approved or rejectd).
 *
 */
void ui_action_validate_signature(bool choice);

/**
 * Action for shared key validation and export.
 *
 * @param[in] choice
 *   User choice (either approved or rejectd).
 *
 */
void ui_action_validate_sharedkey(bool choice);