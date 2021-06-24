

#include <string.h>  // memset, explicit_bzero
#include "re_address.h"
#include "../common/bech32_encode.h"
// #include "../macros.h"  // ASSERT
#include "../bridge.h"  // PRINTF

bool parse_re_address(buffer_t *buffer,
                      parse_address_failure_reason_e *failure_reason,
                      re_address_t *address) {
    uint8_t address_type_value;
    if (!buffer_read_u8(buffer, &address_type_value) ||
        !is_re_address_type_known((int) address_type_value)) {
        *failure_reason = PARSE_ADDRESS_FAIL_UNRECOGNIZED_ADDRESS_TYPE;
        return false;
    }

    if (!is_re_address_type_supported((int) address_type_value)) {
        *failure_reason = PARSE_ADDRESS_FAIL_UNSUPPORTED_ADDRESS_TYPE;
        return false;
    }
    re_address_type_e address_type = (re_address_type_e) address_type_value;

    // print_re_address_type(address_type);

    address->address_type = address_type;

    switch (address_type) {
        case RE_ADDRESS_NATIVE_TOKEN:
            break;
        case RE_ADDRESS_HASHED_KEY_NONCE:
            if (!buffer_move_fill_target(buffer, address->hashed_key, RE_ADDR_HASHED_KEY_LEN)) {
                *failure_reason = PARSE_ADDRESS_FAIL_HASHEDKEY_NOT_ENOUGH_BYTES;
                return false;
            }
            break;
        case RE_ADDRESS_PUBLIC_KEY:
            if (!buffer_move_fill_target(buffer,
                                         address->public_key.compressed,
                                         PUBLIC_KEY_COMPRESSED_LEN)) {
                *failure_reason = PARSE_ADDRESS_FAIL_PUBKEY_NOT_ENOUGH_BYTES;
                return false;
            }
            break;
    }

    return true;
}

/**
 * @brief Bech32 encodes HRP || DATA (`in`) and sets `dst_len` to actual length.
 *
 * @param[in] hrp The Bech32 Human Readable Part, text before delimiter `1`
 * @param[in] hrp_len Length of `hrp`, as in number of chars.
 * @param[in] in The Data part to encode, typically a compressed public key.
 * @param[in] in_len Legnth of `in` data, as in byte count.
 * @param[out] dst The target string to store Bech32 encoded string in.
 * @param[in,out] dst_len The length of `dst` string, which will be overridden with the actual
 * length.
 * @return true If bech32 encoding was successful
 * @return false If bech32 encoding was unsuccessful
 */
static bool abstract_addr_from_bytes(char *hrp,
                                     size_t hrp_len,

                                     const uint8_t *in,
                                     size_t in_len,

                                     char *dst,
                                     size_t *dst_len) {
    UNUSED(hrp_len);
    explicit_bzero(dst, *dst_len);

    if (in_len > MAX_BECH32_DATA_PART_BYTE_COUNT) {
        return false;
    }

    uint8_t tmp_data[MAX_BECH32_DATA_PART_BYTE_COUNT];
    explicit_bzero(tmp_data, sizeof(tmp_data));

    size_t tmp_size = 0;
    int pad = 1;  // use padding
    convert_bits(tmp_data, &tmp_size, 5, in, in_len, 8, pad);
    if (tmp_size >= *dst_len) {
        return false;
    }

    if (!bech32_encode(dst, hrp, tmp_data, &tmp_size)) {
        return false;
    }
    // Set actual size
    *dst_len = tmp_size;

    return true;
}

/**
 * @brief Bech32 encodes an `re_address` according to rules of the Radix ecosystem.
 *
 * @param[in] re_address A Radix Engine address to encode.
 * @param[in] type_if_pubkey If the re_address is of type `RE_ADDRESS_PUBLIC_KEY` this param decides
 * if it is a Validator or an Account address. Set to `DISPLAY_TYPE_IRRELEVANT_NOT_USED` if the
 * address isn't a `RE_ADDRESS_PUBLIC_KEY` type.
 * @param[in] rri_hrp Optional, if the re_address is of type `RE_ADDRESS_HASHED_KEY_NONCE`, this
 * string contains the prefix of the HRP, e.g. "xrd", and the second part of the HRP will be `_rr`
 * (for mainnet). Forming a HRP of `xrd_rr`. Set to NULL if the
 * address isn't a `RE_ADDRESS_HASHED_KEY_NONCE` type.
 * @param[in] rri_hrp_len Set this to the length of `rri_hrp` if not NULL, else set it to 0.
 * @param[out] out The target string to store Bech32 encoded string in.
 * @param[in] out_len The length of `out` string.
 * @return true If bech32 encoding was successful
 * @return false If bech32 encoding was unsuccessful
 */
static bool __to_string_re_address(re_address_t *re_address,
                                   re_display_type_address_e type_if_pubkey,

                                   char *rri_hrp,
                                   const size_t rri_hrp_len,

                                   char *out,
                                   const size_t out_len) {
    bool is_mainnet = false;  // TODO MAINNET change this

    if (rri_hrp && rri_hrp_len == 0) {
        return false;
    }

    if (!rri_hrp && rri_hrp_len > 0) {
        return false;
    }

    uint8_t data[PUBLIC_KEY_COMPRESSED_LEN + 1];  // max length, +1 for version byte
    size_t data_len = 0;

    // will be overridden in case of validator address
    memset(data, re_address->address_type, 1);
    data_len += 1;

    char hrp[MAX_BECH32_HRP_PART_LEN];
    explicit_bzero(hrp, sizeof(hrp));

    size_t hrp_len = 0;

    switch (re_address->address_type) {
        case RE_ADDRESS_NATIVE_TOKEN:  // RRI - XRD

            // Set HRP
            hrp_len = RRI_HRP_PREFIX_NATIVE_TOKEN_LEN;
            strncpy(hrp, RRI_HRP_PREFIX_NATIVE_TOKEN, hrp_len);
            break;
        case RE_ADDRESS_HASHED_KEY_NONCE:  // RRI - Other
            // Set HRP
            memmove(hrp, rri_hrp, rri_hrp_len);
            hrp_len = rri_hrp_len;
            // Set 'data'
            memmove(data + 1, re_address->hashed_key, RE_ADDR_HASHED_KEY_LEN);
            data_len += RE_ADDR_HASHED_KEY_LEN;
            break;
        case RE_ADDRESS_PUBLIC_KEY:  // Account address or Validator address
            switch (type_if_pubkey) {
                case DISPLAY_TYPE_IRRELEVANT_NOT_USED:
                    return false;
                case DISPLAY_TYPE_ACCOUNT_ADDRESS:
                    // Set HRP
                    hrp_len = ACCOUNT_ADDRESS_HRP_LENGTH;
                    if (is_mainnet) {
                        memmove(hrp, ACCOUNT_ADDRESS_HRP_MAINNET, hrp_len);
                    } else {
                        memmove(hrp, ACCOUNT_ADDRESS_HRP_BETANET, hrp_len);
                    }
                    memmove(data + 1, re_address->public_key.compressed, PUBLIC_KEY_COMPRESSED_LEN);
                    data_len += PUBLIC_KEY_COMPRESSED_LEN;
                    break;
                case DISPLAY_TYPE_VALIDATOR_ADDRESS:
                    hrp_len = VALIDATOR_ADDRESS_HRP_LENGTH;
                    if (is_mainnet) {
                        memmove(hrp, VALIDATOR_ADDRESS_HRP_MAINNET, hrp_len);
                    } else {
                        memmove(hrp, VALIDATOR_ADDRESS_HRP_BETANET, hrp_len);
                    }
                    memmove(data, re_address->public_key.compressed, PUBLIC_KEY_COMPRESSED_LEN);
                    data_len = PUBLIC_KEY_COMPRESSED_LEN;
                    break;
            }
            break;
    }

    bool is_rri = re_address->address_type == RE_ADDRESS_NATIVE_TOKEN ||
                  re_address->address_type == RE_ADDRESS_HASHED_KEY_NONCE;
    if (is_rri) {
        if (is_mainnet) {
            memmove(hrp + hrp_len, RRI_HRP_SUFFIX_MAINNET, RRI_HRP_SUFFIX_LEN);
        } else {
            memmove(hrp + hrp_len, RRI_HRP_SUFFIX_BETANET, RRI_HRP_SUFFIX_LEN);
        }

        hrp_len += RRI_HRP_SUFFIX_LEN;
    }

    if (hrp_len > MAX_BECH32_HRP_PART_LEN) {
        PRINTF("RRI HRP too long\n");
        return false;
    }

    size_t actual_len = out_len;
    if (!abstract_addr_from_bytes(hrp, hrp_len, data, data_len, out, &actual_len) ||
        actual_len > out_len) {
        return false;
    }

    return true;
}

/**
 * @brief Bech32 encodes an `re_address` of type `RE_ADDRESS_PUBLIC_KEY` to either a Validator
 * Address or an Account Address.
 *
 * @param[in] re_address A Radix Engine address to encode.
 * @param[in] type_if_pubkey Decides if it is a Validator or an Account address.
 * @param[out] out The target string to store Bech32 encoded string in.
 * @param[in] out_len The length of `out` string.
 *
 * @return true If bech32 encoding was successful
 * @return false If bech32 encoding was unsuccessful
 */
static bool __format_account_or_validator_address_from_re_address(
    re_address_t *re_address,
    re_display_type_address_e display_type,
    char *out,
    const size_t out_len) {
    // ASSERT(re_address->address_type == RE_ADDRESS_PUBLIC_KEY,
    //    "re_address is not RE_ADDRESS_PUBLIC_KEY");

    if (re_address->address_type != RE_ADDRESS_PUBLIC_KEY) {
        PRINTF("re_address is not RE_ADDRESS_PUBLIC_KEY\n");
        return false;
    }

    // ASSERT(display_type != DISPLAY_TYPE_IRRELEVANT_NOT_USED,
    //    "Display style must be `DISPLAY_TYPE_VALIDATOR_ADDRESS` or "
    //    "`DISPLAY_TYPE_ACCOUNT_ADDRESS`'");

    if (display_type == DISPLAY_TYPE_IRRELEVANT_NOT_USED) {
        PRINTF(
            "Display style must be `DISPLAY_TYPE_VALIDATOR_ADDRESS` or "
            "`DISPLAY_TYPE_ACCOUNT_ADDRESS`'\n");
        return false;
    }

    if (!__to_string_re_address(re_address, display_type, NULL, 0, out, out_len)) {
        return false;
    }

    return true;
}

bool format_account_address_from_re_address(re_address_t *re_address,
                                            char *out,
                                            const size_t out_len) {
    // ASSERT(out_len >= ACCOUNT_ADDRESS_LEN, "Output string is too short.");
    if (out_len < ACCOUNT_ADDRESS_LEN) {
        PRINTF("Output string is too short.\n");
        return false;
    }

    return __format_account_or_validator_address_from_re_address(re_address,
                                                                 DISPLAY_TYPE_ACCOUNT_ADDRESS,
                                                                 out,
                                                                 out_len);
}

bool format_validator_address_from_re_address(re_address_t *re_address,
                                              char *out,
                                              const size_t out_len) {
    // ASSERT(out_len >= VALIDATOR_ADDRESS_LEN, "Output string is too short.");
    if (out_len < VALIDATOR_ADDRESS_LEN) {
        PRINTF("Output string is too short.\n");
        return false;
    }

    return __format_account_or_validator_address_from_re_address(re_address,
                                                                 DISPLAY_TYPE_VALIDATOR_ADDRESS,
                                                                 out,
                                                                 out_len);
}

bool format_native_token_from_re_address(re_address_t *re_address,
                                         char *out,
                                         const size_t out_len) {
    // ASSERT(re_address->address_type == RE_ADDRESS_NATIVE_TOKEN, "re_address is not
    // NATIVE_TOKEN");
    if (re_address->address_type != RE_ADDRESS_NATIVE_TOKEN) {
        PRINTF("re_address is not NATIVE_TOKEN\n");
        return false;
    }
    // ASSERT(out_len >= NATIVE_TOKEN_LEN, "Output string is too short.");
    if (out_len < NATIVE_TOKEN_LEN) {
        PRINTF("Output string is too short.\n");
        return false;
    }
    return __to_string_re_address(re_address,
                                  DISPLAY_TYPE_IRRELEVANT_NOT_USED,
                                  NULL,
                                  0,
                                  out,
                                  out_len);
}

bool format_other_token_from_re_address(re_address_t *re_address,
                                        char *rri_hrp,
                                        const size_t rri_hrp_len,
                                        char *out,
                                        const size_t out_len) {
    // ASSERT(re_address->address_type == RE_ADDRESS_HASHED_KEY_NONCE,
    //    "re_address is not HASHED_KEY_NONCE");

    if (re_address->address_type != RE_ADDRESS_HASHED_KEY_NONCE) {
        PRINTF("re_address is not HASHED_KEY_NONCE\n");
        return false;
    }

    return __to_string_re_address(re_address,
                                  DISPLAY_TYPE_IRRELEVANT_NOT_USED,
                                  rri_hrp,
                                  rri_hrp_len,
                                  out,
                                  out_len);
}