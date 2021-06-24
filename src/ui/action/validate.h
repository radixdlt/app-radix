#pragma once

#include <stdbool.h>  // bool

#include "../../state.h"  // bool user_accepted_t

/**
 * Action for public key validation and export.
 *
 * @param[in] choice
 *   User choice (either approved or rejectd).
 *
 */
void ui_action_validate_pubkey(user_accepted_t user_accepted);

/**
 * Action for signature information validation.
 * From sign hash flow.
 *
 * @param[in] user_accepted
 *   User choice (either approved or rejectd).
 *
 */
void ui_action_validate_sign_hash(user_accepted_t user_accepted);

/**
 * Action for signature information validation.
 * From sign tx flow. Differs a bit from sign
 * hash flow, because we should respond with
 * calculated hash back to host machine.
 *
 * @param[in] user_accepted
 *   User choice (either approved or rejectd).
 *
 */
void ui_action_validate_sign_tx(user_accepted_t user_accepted);

/**
 * Action for shared key validation and export.
 *
 * @param[in] user_accepted
 *   User choice (either approved or rejectd).
 *
 */
void ui_action_validate_sharedkey(user_accepted_t user_accepted);

/**
 * @brief Action for single parsed instruction validation.
 *
 * @param[in] user_accepted User choice (either approved or rejectd).
 */
void ui_action_validate_instruction(user_accepted_t user_accepted);