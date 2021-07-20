#pragma once

#include "buffer.h"
#include "re_address_type.h"
#include "../constants.h"
#include "public_key.h"

#define VALIDATOR_ADDRESS_HRP_LENGTH (networks[APPNETWORK].validator_hrp_len)
#define VALIDATOR_ADDRESS_HRP        (networks[APPNETWORK].validator_hrp)
#define ACCOUNT_ADDRESS_HRP_LENGTH   (networks[APPNETWORK].account_hrp_len)
#define ACCOUNT_ADDRESS_HRP          (networks[APPNETWORK].account_hrp)
#define RRI_HRP_SUFFIX_LEN           (networks[APPNETWORK].resource_hrp_len)
#define RRI_HRP_SUFFIX               (networks[APPNETWORK].resource_hrp)

#define RRI_HRP_PREFIX_NATIVE_TOKEN     "xrd"
#define RRI_HRP_PREFIX_NATIVE_TOKEN_LEN (sizeof(RRI_HRP_PREFIX_NATIVE_TOKEN) - 1)

#define RE_ADDR_HASHED_KEY_LEN 26
#define VALIDATOR_ADDRESS_LEN  62
#define ACCOUNT_ADDRESS_LEN    65
#define NATIVE_TOKEN_LEN       (networks[APPNETWORK].resource_hrp_len + 12)

/**
 * @brief Display type for a RE address of PublicKey type.
 *
 */
typedef enum {
    DISPLAY_TYPE_IRRELEVANT_NOT_USED,
    DISPLAY_TYPE_ACCOUNT_ADDRESS,
    DISPLAY_TYPE_VALIDATOR_ADDRESS,
} re_display_type_address_e;

/**
 * Structure for a Radix Engine address.
 */
typedef struct {
    re_address_type_e address_type;  /// Type of RE address
    union {
        uint8_t hashed_key[RE_ADDR_HASHED_KEY_LEN];  /// If `RE_ADDRESS_HASHED_KEY_NONCE`
        public_key_t public_key;                     /// If `RE_ADDRESS_PUBLIC_KEY`
    };
} re_address_t;

typedef enum {
    PARSE_ADDRESS_FAIL_UNRECOGNIZED_ADDRESS_TYPE,
    PARSE_ADDRESS_FAIL_UNSUPPORTED_ADDRESS_TYPE,
    PARSE_ADDRESS_FAIL_HASHEDKEY_NOT_ENOUGH_BYTES,
    PARSE_ADDRESS_FAIL_PUBKEY_NOT_ENOUGH_BYTES,
    PARSED_ADDRESS_FAIL_EXPECTED_TYPE_COMPATIBLE_WITH_RESOURCE,
    PARSED_ADDRESS_FAIL_EXPECTED_TYPE_COMPATIBLE_ACCOUNT_OR_VALIDATOR_ADDRESS,
} parse_address_failure_reason_e;

/**
 * @brief Parse an abstract `re_address` from a buffer.
 *
 * Parse an abstract \struct re_address_t from the \p buffer, if successful, put outcome in \p
 * address and return true, else if failure, specify reason in \p failure_reason and return false.
 *
 * @param[in] buffer Buffer to read bytes from.
 * @param[out] failure_reason If parsing failed this contains the reason.
 * @param[out] address
 * @return true If parsing was successful
 * @return false If parsing was unsuccessful
 */
bool parse_re_address(buffer_t *buffer,
                      parse_address_failure_reason_e *failure_reason,
                      re_address_t *address);

/**
 * @brief Formats an abstract `re_address` as an account address.
 *
 * Bech32 encodes an `re_address` of type `RE_ADDRESS_PUBLIC_KEY` as an account address.
 *
 * @param[in] re_address A Radix Engine address to encode, must have type `RE_ADDRESS_PUBLIC_KEY`.
 * @param[out] out The target string to store Bech32 encoded string in.
 * @param[in] out_len The length of `out` string.
 * @return true If bech32 encoding was successful
 * @return false If bech32 encoding was unsuccessful
 */
bool format_account_address_from_re_address(re_address_t *re_address,
                                            char *out,
                                            const size_t out_len);

/**
 * @brief Formats an abstract `re_address` as a validator address.
 *
 * Bech32 encodes an `re_address` of type `RE_ADDRESS_PUBLIC_KEY` as a validator address.
 *
 * @param[in] re_address A Radix Engine address to encode, must have type `RE_ADDRESS_PUBLIC_KEY`.
 * @param[out] out The target string to store Bech32 encoded string in.
 * @param[in] out_len The length of `out` string.
 * @return true If bech32 encoding was successful
 * @return false If bech32 encoding was unsuccessful
 */
bool format_validator_address_from_re_address(re_address_t *re_address,
                                              char *out,
                                              const size_t out_len);

/**
 * @brief Formats an abstract `re_address` as an RRI for the native token.
 *
 * Bech32 encodes an `re_address` of type `RE_ADDRESS_NATIVE_TOKEN`.
 *
 * @param[in] re_address A Radix Engine address to encode, must have type `RE_ADDRESS_NATIVE_TOKEN`.
 * @param[out] out The target string to store Bech32 encoded string in.
 * @param[in] out_len The length of `out` string.
 * @return true If bech32 encoding was successful
 * @return false If bech32 encoding was unsuccessful
 */
bool format_native_token_from_re_address(re_address_t *re_address, char *out, const size_t out_len);

/**
 * @brief Formats an abstract `re_address` as an RRI for a non-native token.
 *
 * Bech32 encodes an `re_address` of type `RE_ADDRESS_HASHED_KEY_NONCE` with the provided HRP
 * prefix.
 *
 * @param[in] re_address A Radix Engine address to encode, must have type
 * `RE_ADDRESS_HASHED_KEY_NONCE`.
 * @param[in] rri_hrp This string contains the prefix of the HRP, e.g. "xrd", and the second part of
 * the HRP will be `_rr` (for mainnet). Forming a HRP of `xrd_rr`.
 * @param[in] rri_hrp_len The length of `rri_hrp`.
 * @param[out] out The target string to store Bech32 encoded string in.
 * @param[in] out_len The length of `out` string.
 * @return true If bech32 encoding was successful
 * @return false If bech32 encoding was unsuccessful
 */
bool format_other_token_from_re_address(re_address_t *re_address,
                                        char *rri_hrp,
                                        const size_t rri_hrp_len,
                                        char *out,
                                        const size_t out_len);