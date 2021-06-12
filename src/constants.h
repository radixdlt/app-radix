#pragma once

/**
 * Instruction class of the Radix application.
 */
#define CLA 0xAA

/**
 * Length of APPNAME variable in the Makefile.
 */
#define APPNAME_LEN (sizeof(APPNAME) - 1)

/**
 * Maximum length of MAJOR_VERSION || MINOR_VERSION || PATCH_VERSION.
 */
#define APPVERSION_LEN 3

/**
 * Maximum length of application name.
 */
#define MAX_APPNAME_LEN 64

/**
 * Maximum transaction length (bytes).
 */
#define MAX_TRANSACTION_LEN 510

/**
 * Maximum signature length (bytes).
 */
#define MAX_DER_SIG_LEN 72

/**
 * Exponent used to convert attoXRD to XRD unit (N XRD = N * 10^18 attoBOL).
 */
#define EXPONENT_SMALLEST_UNIT 18

/**
 * @brief Length of a PrivateKey
 * Length of PrivateKey (bytes).
 */
#define PRIVATE_KEY_LEN 32

/**
 * @brief Length of a Hash
 * Length of SHA256 Digest (bytes).
 */
#define HASH_LEN 32

/**
 * @brief Length of Chain code
 * Length of Chain code (bytes).
 */
#define CHAIN_CODE_LEN 32

/**
 * @brief Length of PublicKey on compressed format
 * Length of a PublicKey on compressed format (bytes).
 */
#define PUBLIC_KEY_COMPRESSED_LEN 33

/**
 * @brief Length of PublicKey on uncompressed format
 * Length of a PublicKey on uncompressed format (bytes).
 */
#define PUBLIC_KEY_UNCOMPRESSEED_LEN 64

/**
 * @brief Length of PublicKey POINT on uncompressed format
 * Length of a PublicKey POINT (bytes).
 */
#define PUBLIC_KEY_POINT_LEN (PUBLIC_KEY_UNCOMPRESSEED_LEN + 1)  // 1 byte flag

#define PUBKEY_FLAG_KEY_IS_UNCOMPRESSED         0x04
#define PUBKEY_FLAG_KEY_IS_COMPRESSED_Y_IS_EVEN 0x02
#define PUBKEY_FLAG_KEY_IS_COMPRESSED_Y_IS_ODD  0x03