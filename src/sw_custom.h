#pragma once

// Keep in sync with
// https://github.com/radixdlt/radixdlt-javascript/blob/main/packages/hardware-ledger/src/_types.ts#L13

// ALL CUSTOM CODES MUST BE IN THIS RANGE: 0xB000 - 0xEFFF
// See below:
// https://github.com/LedgerHQ/nanos-secure-sdk/blob/master/include/errors.h#L45-L52

// Generic identifiers.
enum generic_identifiers_radix {
    ERR_BYTE_00 = 0x00,
    ERR_BYTE_01 = 0x01,
    ERR_BYTE_02,
    ERR_BYTE_03,
    ERR_BYTE_04,
    ERR_BYTE_05,
    ERR_BYTE_06,
    ERR_BYTE_07,
    ERR_BYTE_08,
    ERR_BYTE_09,
    ERR_BYTE_0A,
    ERR_BYTE_0B,
    ERR_BYTE_0C,
    ERR_BYTE_0D,
    ERR_BYTE_0E,
    ERR_BYTE_0F,
    ERR_BYTE_10,
    ERR_BYTE_11,
    ERR_BYTE_12,
    ERR_BYTE_13,
    ERR_BYTE_14,
    ERR_BYTE_15,
    ERR_BYTE_16,
    ERR_BYTE_17,
    ERR_BYTE_18,
    ERR_BYTE_19,
    ERR_BYTE_1A,
    ERR_BYTE_1B,
    ERR_BYTE_1C,
    ERR_BYTE_1D,
    ERR_BYTE_1E,
    ERR_BYTE_1F,
    ERR_BYTE_20,
    ERR_BYTE_21,
    ERR_BYTE_22,
    ERR_BYTE_23,
    ERR_BYTE_24,
    ERR_BYTE_25,
    ERR_BYTE_26,
    ERR_BYTE_27,
    ERR_BYTE_28,
    ERR_BYTE_29,
    ERR_BYTE_2A,
    ERR_BYTE_2B,
    ERR_BYTE_2C,
    ERR_BYTE_2D,
    ERR_BYTE_2E,
    ERR_BYTE_2F,
    ERR_BYTE_30,
    ERR_BYTE_31,
    ERR_BYTE_32,
    ERR_BYTE_33,
    ERR_BYTE_34,
    ERR_BYTE_35,
    ERR_BYTE_36,
    ERR_BYTE_37,
    ERR_BYTE_38,
    ERR_BYTE_39,
    ERR_BYTE_3A,
    ERR_BYTE_3B,
    ERR_BYTE_3C,
    ERR_BYTE_3D,
    ERR_BYTE_3E,
    ERR_BYTE_3F,
    ERR_BYTE_40,
    ERR_BYTE_41,
    ERR_BYTE_42,
    ERR_BYTE_43,
    ERR_BYTE_44,
    ERR_BYTE_45,
    ERR_BYTE_46,
    ERR_BYTE_47,
    ERR_BYTE_48,
    ERR_BYTE_49,
    ERR_BYTE_4A,
    ERR_BYTE_4B,
    ERR_BYTE_4C,
    ERR_BYTE_4D,
    ERR_BYTE_4E,
    ERR_BYTE_4F,
    ERR_BYTE_50,
    ERR_BYTE_51,
    ERR_BYTE_52,
    ERR_BYTE_53,
    ERR_BYTE_54,
    ERR_BYTE_55,
    ERR_BYTE_56,
    ERR_BYTE_57,
    ERR_BYTE_58,
    ERR_BYTE_59,
    ERR_BYTE_5A,
    ERR_BYTE_5B,
    ERR_BYTE_5C,
    ERR_BYTE_5D,
    ERR_BYTE_5E,
    ERR_BYTE_5F,
    ERR_BYTE_60,
    ERR_BYTE_61,
    ERR_BYTE_62,
    ERR_BYTE_63,
    ERR_BYTE_64,
    ERR_BYTE_65,
    ERR_BYTE_66,
    ERR_BYTE_67,
    ERR_BYTE_68,
    ERR_BYTE_69,
    ERR_BYTE_6A,
    ERR_BYTE_6B,
    ERR_BYTE_6C,
    ERR_BYTE_6D,
    ERR_BYTE_6E,
    ERR_BYTE_6F,
    ERR_BYTE_70,
    ERR_BYTE_71,
    ERR_BYTE_72,
    ERR_BYTE_73,
    ERR_BYTE_74,
    ERR_BYTE_75,
    ERR_BYTE_76,
    ERR_BYTE_77,
    ERR_BYTE_78,
    ERR_BYTE_79,
    ERR_BYTE_7A,
    ERR_BYTE_7B,
    ERR_BYTE_7C,
    ERR_BYTE_7D,
    ERR_BYTE_7E,
    ERR_BYTE_7F,
    ERR_BYTE_80,
    ERR_BYTE_81,
    ERR_BYTE_82,
    ERR_BYTE_83,
    ERR_BYTE_84,
    ERR_BYTE_85,
    ERR_BYTE_86,
    ERR_BYTE_87,
    ERR_BYTE_88,
    ERR_BYTE_89,
    ERR_BYTE_8A,
    ERR_BYTE_8B,
    ERR_BYTE_8C,
    ERR_BYTE_8D,
    ERR_BYTE_8E,
    ERR_BYTE_8F,
    ERR_BYTE_90,
    ERR_BYTE_91,
    ERR_BYTE_92,
    ERR_BYTE_93,
    ERR_BYTE_94,
    ERR_BYTE_95,
    ERR_BYTE_96,
    ERR_BYTE_97,
    ERR_BYTE_98,
    ERR_BYTE_99,
    ERR_BYTE_9A,
    ERR_BYTE_9B,
    ERR_BYTE_9C,
    ERR_BYTE_9D,
    ERR_BYTE_9E,
    ERR_BYTE_9F,
    ERR_BYTE_A0,
    ERR_BYTE_A1,
    ERR_BYTE_A2,
    ERR_BYTE_A3,
    ERR_BYTE_A4,
    ERR_BYTE_A5,
    ERR_BYTE_A6,
    ERR_BYTE_A7,
    ERR_BYTE_A8,
    ERR_BYTE_A9,
    ERR_BYTE_AA,
    ERR_BYTE_AB,
    ERR_BYTE_AC,
    ERR_BYTE_AD,
    ERR_BYTE_AE,
    ERR_BYTE_AF,
    ERR_BYTE_B0,
    ERR_BYTE_B1,
    ERR_BYTE_B2,
    ERR_BYTE_B3,
    ERR_BYTE_B4,
    ERR_BYTE_B5,
    ERR_BYTE_B6,
    ERR_BYTE_B7,
    ERR_BYTE_B8,
    ERR_BYTE_B9,
    ERR_BYTE_BA,
    ERR_BYTE_BB,
    ERR_BYTE_BC,
    ERR_BYTE_BD,
    ERR_BYTE_BE,
    ERR_BYTE_BF,
    ERR_BYTE_C0,
    ERR_BYTE_C1,
    ERR_BYTE_C2,
    ERR_BYTE_C3,
    ERR_BYTE_C4,
    ERR_BYTE_C5,
    ERR_BYTE_C6,
    ERR_BYTE_C7,
    ERR_BYTE_C8,
    ERR_BYTE_C9,
    ERR_BYTE_CA,
    ERR_BYTE_CB,
    ERR_BYTE_CC,
    ERR_BYTE_CD,
    ERR_BYTE_CE,
    ERR_BYTE_CF,
    ERR_BYTE_D0,
    ERR_BYTE_D1,
    ERR_BYTE_D2,
    ERR_BYTE_D3,
    ERR_BYTE_D4,
    ERR_BYTE_D5,
    ERR_BYTE_D6,
    ERR_BYTE_D7,
    ERR_BYTE_D8,
    ERR_BYTE_D9,
    ERR_BYTE_DA,
    ERR_BYTE_DB,
    ERR_BYTE_DC,
    ERR_BYTE_DD,
    ERR_BYTE_DE,
    ERR_BYTE_DF,
    ERR_BYTE_E0,
    ERR_BYTE_E1,
    ERR_BYTE_E2,
    ERR_BYTE_E3,
    ERR_BYTE_E4,
    ERR_BYTE_E5,
    ERR_BYTE_E6,
    ERR_BYTE_E7,
    ERR_BYTE_E8,
    ERR_BYTE_E9,
    ERR_BYTE_EA,
    ERR_BYTE_EB,
    ERR_BYTE_EC,
    ERR_BYTE_ED,
    ERR_BYTE_EE,
    ERR_BYTE_EF,
    ERR_BYTE_F0,
    ERR_BYTE_F1,
    ERR_BYTE_F2,
    ERR_BYTE_F3,
    ERR_BYTE_F4,
    ERR_BYTE_F5,
    ERR_BYTE_F6,
    ERR_BYTE_F7,
    ERR_BYTE_F8,
    ERR_BYTE_F9,
    ERR_BYTE_FA,
    ERR_BYTE_FB,
    ERR_BYTE_FC,
    ERR_BYTE_FD,
    ERR_BYTE_FE,
    ERR_BYTE_FF,
};

// Generic subcategories.
#define ERR_GEN_SUB_01 0x0100
#define ERR_GEN_SUB_02 0x0200
#define ERR_GEN_SUB_03 0x0300
#define ERR_GEN_SUB_04 0x0400
#define ERR_GEN_SUB_05 0x0500
#define ERR_GEN_SUB_06 0x0600
#define ERR_GEN_SUB_07 0x0700
#define ERR_GEN_SUB_08 0x0800
#define ERR_GEN_SUB_09 0x0900
#define ERR_GEN_SUB_0D 0x0D00
#define ERR_GEN_SUB_0E 0x0E00

/// $$$$$$$$$$$$$$$$$$$$$$$$$$$$
/// $$   C: Command (CXXX)    $$
/// $$$$$$$$$$$$$$$$$$$$$$$$$$$$
#define ERR_CMD_RANGE 0xC000

#define ERR_CMD_PARSE_APDU (ERR_CMD_RANGE + ERR_GEN_SUB_01)

/**
 * Status word for wrong reponse length (buffer too small or too big).
 */
#define ERR_CMD_PARSE_APDU_RESPONSE_LENGTH (ERR_CMD_PARSE_APDU + ERR_BYTE_01)

/// *-------------------------------*
/// |  CMD: GET_VERSION (C3XX)      |
/// *-------------------------------*
#define ERR_CMD_GET_VERSION (ERR_CMD_RANGE + ERR_GEN_SUB_03)

/// *-------------------------------*
/// |  CMD: GET_APP_NAME (C4XX)     |
/// *-------------------------------*
#define ERR_CMD_GET_APP_NAME (ERR_CMD_RANGE + ERR_GEN_SUB_04)

/// *-------------------------------*
/// |  CMD: GET_PUBLIC_KEY (C5XX)   |
/// *-------------------------------*
#define ERR_CMD_GET_PUBLIC_KEY (ERR_CMD_RANGE + ERR_GEN_SUB_05)

#define ERR_CMD_GET_PUBLIC_KEY_FAILED_TO_COMPRESS_KEY (ERR_CMD_GET_PUBLIC_KEY + ERR_BYTE_10)

/// *-------------------------------*
/// |  CMD: SIGN_TX (C6XX)          |
/// *-------------------------------*
#define ERR_CMD_SIGN_TX (ERR_CMD_RANGE + ERR_GEN_SUB_06)

// -=: PARSE APDU :=- (C600-C60F)
#define ERR_CMD_SIGN_TX_PARSE_BIP32_PATH_FAILURE        (ERR_CMD_SIGN_TX + ERR_BYTE_01)
#define ERR_CMD_SIGN_TX_PARSE_TX_SIZE_FAILURE           (ERR_CMD_SIGN_TX + ERR_BYTE_02)
#define ERR_CMD_SIGN_TX_PARSE_INSTRUCTION_COUNT_FAILURE (ERR_CMD_SIGN_TX + ERR_BYTE_03)

#define ERR_CMD_SIGN_TX_PARSE_HRP_LEN_FAILURE    (ERR_CMD_SIGN_TX + ERR_BYTE_04)
#define ERR_CMD_SIGN_TX_PARSE_HRP_TOO_LONG       (ERR_CMD_SIGN_TX + ERR_BYTE_05)
#define ERR_CMD_SIGN_TX_PARSE_HRP_FAILED_TO_READ (ERR_CMD_SIGN_TX + ERR_BYTE_06)

#define ERR_CMD_SIGN_TX_INVALID_CONFIG (ERR_CMD_SIGN_TX + ERR_BYTE_07)

#define ERR_CMD_SIGN_TX_UNRECOGNIZED_INSTRUCTION_TYPE  (ERR_CMD_SIGN_TX + ERR_BYTE_08)
#define ERR_CMD_SIGN_TX_UNSUPPORTED_INSTRUCTION_TYPE   (ERR_CMD_SIGN_TX + ERR_BYTE_09)
#define ERR_CMD_SIGN_TX_FAILED_TO_COMPRESS_MY_KEY      (ERR_CMD_SIGN_TX + ERR_BYTE_0A)
#define ERR_CMD_SIGN_TX_PARSE_TX_FEE_FROM_SYSCALL_FAIL (ERR_CMD_SIGN_TX + ERR_BYTE_0B)
#define ERR_CMD_SIGN_TX_TX_DID_NOT_CONTAIN_TX_FEE      (ERR_CMD_SIGN_TX + ERR_BYTE_0C)

// PARSE SUBSTATE INDEX (C610-C61F)
#define ERR_CMD_SIGN_TX_SUBSTATE_INDEX_PARSE_FAILURE (ERR_CMD_SIGN_TX + ERR_BYTE_10)

// PARSE SUBSTATE ID (C620-C62F)
#define ERR_CMD_SIGN_TX_SUBSTATE_ID_HASH_PARSE_FAILURE  (ERR_CMD_SIGN_TX + ERR_BYTE_20)
#define ERR_CMD_SIGN_TX_SUBSTATE_ID_INDEX_PARSE_FAILURE (ERR_CMD_SIGN_TX + ERR_BYTE_21)

// PARSE SUBSTATE (C630-C66F)
// =:Parse Substate Common:= (C630-C63F) size: 16
#define ERR_CMD_SIGN_TX_UNRECOGNIZED_SUBSTATE_TYPE (ERR_CMD_SIGN_TX + ERR_BYTE_30)
#define ERR_CMD_SIGN_TX_UNSUPPORTED_SUBSTATE_TYPE  (ERR_CMD_SIGN_TX + ERR_BYTE_31)

#define ERR_CMD_SIGN_TX_PARSE_BYTES_LENGTH_FAILURE (ERR_CMD_SIGN_TX + ERR_BYTE_32)
#define ERR_CMD_SIGN_TX_PARSE_BYTES_WRONG_LENGTH   (ERR_CMD_SIGN_TX + ERR_BYTE_33)

// Parse Tokens (C640-C64F) size: 16
#define ERR_CMD_SIGN_TX_TOKENS_PARSE_RRI_FAILURE    (ERR_CMD_SIGN_TX + ERR_BYTE_40)
#define ERR_CMD_SIGN_TX_TOKENS_PARSE_OWNER_FAILURE  (ERR_CMD_SIGN_TX + ERR_BYTE_41)
#define ERR_CMD_SIGN_TX_TOKENS_PARSE_AMOUNT_FAILURE (ERR_CMD_SIGN_TX + ERR_BYTE_42)

// Parse Stake (C650-C65F) size: 16
#define ERR_CMD_SIGN_TX_PREPARED_STAKE_PARSE_OWNER_FAILURE    (ERR_CMD_SIGN_TX + ERR_BYTE_50)
#define ERR_CMD_SIGN_TX_PREPARED_STAKE_PARSE_DELEGATE_FAILURE (ERR_CMD_SIGN_TX + ERR_BYTE_51)
#define ERR_CMD_SIGN_TX_PREPARED_STAKE_PARSE_AMOUNT_FAILURE   (ERR_CMD_SIGN_TX + ERR_BYTE_52)

// Parse Unstake (C660-C66F) size: 16
#define ERR_CMD_SIGN_TX_PREPARED_UNSTAKE_PARSE_DELEGATE_FAILURE (ERR_CMD_SIGN_TX + ERR_BYTE_60)
#define ERR_CMD_SIGN_TX_PREPARED_UNSTAKE_PARSE_OWNER_FAILURE    (ERR_CMD_SIGN_TX + ERR_BYTE_61)
#define ERR_CMD_SIGN_TX_PREPARED_UNSTAKE_PARSE_AMOUNT_FAILURE   (ERR_CMD_SIGN_TX + ERR_BYTE_62)

// Parse ShareStake (C670-C67F) size: 16
#define ERR_CMD_SIGN_TX_STAKE_SHARE_PARSE_PUBLIC_KEY_FAILURE (ERR_CMD_SIGN_TX + ERR_BYTE_70)
#define ERR_CMD_SIGN_TX_STAKE_SHARE_PARSE_OWNER_FAILURE      (ERR_CMD_SIGN_TX + ERR_BYTE_71)
#define ERR_CMD_SIGN_TX_STAKE_SHARE_PARSE_AMOUNT_FAILURE     (ERR_CMD_SIGN_TX + ERR_BYTE_72)

// Parse instruction
#define ERR_CMD_SIGN_TX_PARSE_INS_SYSCALL (ERR_CMD_SIGN_TX + ERR_BYTE_89)
#define ERR_CMD_SIGN_TX_PARSE_INS_HEADER  (ERR_CMD_SIGN_TX + ERR_BYTE_8A)

// Various exceptions during Sign TX flow
#define ERR_CMD_SIGN_TX_DISABLE_MINT_AND_BURN_FLAG_NOT_SET (ERR_CMD_SIGN_TX + ERR_BYTE_E0)
#define ERR_CMD_SIGN_TX_ECDSA_SIGN_FAIL                    (ERR_CMD_SIGN_TX + ERR_BYTE_E1)
#define ERR_CMD_SIGN_TX_LAST_INSTRUCTION_WAS_NOT_INS_END   (ERR_CMD_SIGN_TX + ERR_BYTE_E2)

/// *-------------------------------*
/// |  CMD: SIGN_HASH (C7XX)        |
/// *-------------------------------*
#define ERR_CMD_SIGN_HASH (ERR_CMD_RANGE + ERR_GEN_SUB_07)

#define ERR_CMD_SIGN_HASH_PARSE_HASH_FAILURE_BAD_LENGTH (ERR_CMD_SIGN_HASH + ERR_BYTE_01)
#define ERR_CMD_SIGN_HASH_PARSE_HASH_FAILURE_TOO_SHORT  (ERR_CMD_SIGN_HASH + ERR_BYTE_02)

#define ERR_CMD_SIGN_HASH_ECDSA_SIGN_FAIL (ERR_CMD_SIGN_HASH + ERR_BYTE_E0)

/// *-------------------------------*
/// |  CMD: ECDH (C8XX)             |
/// *-------------------------------*
#define ERR_CMD_ECDH (ERR_CMD_RANGE + ERR_GEN_SUB_08)

#define ERR_CMD_ECDH_OTHER_PARTY_PUBLIC_KEY_PARSE_FAILURE (ERR_CMD_ECDH + ERR_BYTE_10)
#define ERR_CMD_ECDH_FAILED_TO_COMPRESS_OTHER_PARTY_KEY   (ERR_CMD_ECDH + ERR_BYTE_11)
#define ERR_CMD_ECDH_COMPUTE_SHARED_KEY_FAILURE           (ERR_CMD_ECDH + ERR_BYTE_20)

/// $$$$$$$$$$$$$$$$$$$$$$$$$$$$
/// $$   D: Display (DXXX)    $$
/// $$$$$$$$$$$$$$$$$$$$$$$$$$$$
#define ERR_DISPLAY_RANGE 0xD000

#define ERR_DISPLAY (ERR_DISPLAY_RANGE + ERR_GEN_SUB_01)

#define ERR_DISPLAY_BIP32_PATH_FAIL (ERR_DISPLAY + ERR_BYTE_01)
#define ERR_DISPLAY_ADDRESS_FAIL    (ERR_DISPLAY + ERR_BYTE_02)
#define ERR_DISPLAY_AMOUNT_FAIL     (ERR_DISPLAY + ERR_BYTE_03)
#define ERR_DISPLAY_RRI_FAIL        (ERR_DISPLAY + ERR_BYTE_04)

/// $$$$$$$$$$$$$$$$$$$$$$$$$$$$
/// $$   E: Exception (EXXX)    $$
/// $$$$$$$$$$$$$$$$$$$$$$$$$$$$
#define ERR_EXCEPTION_RANGE 0xE000

#define ERR_BAD_STATE        (ERR_EXCEPTION_RANGE + ERR_BYTE_01)
#define ERR_ASSERTION_FAILED (ERR_EXCEPTION_RANGE + ERR_BYTE_02)
#define ERR_FATAL_ERROR      (ERR_EXCEPTION_RANGE + ERR_BYTE_03)
