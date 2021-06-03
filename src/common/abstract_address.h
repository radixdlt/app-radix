//
//  bech32.h
//  LedgerXcodeProj
//
//  Created by Alexander Cyon on 2021-05-24.
//

#pragma once

#include <stddef.h>   // size_t
#include <stdint.h>   // uint*_t
#include <stdbool.h>  // bool

// arbitrarily chosen
#define MAX_BECH32_DATA_PART_BYTE_COUNT 65

/**
 * Bech32 format (hrp || bytes). If successful, sets `dst_len` to actual length.
 *
 * @param[in]  hrp
 *   Pointer to a Human-Readable Prefix (HRP) string, to be used as prefix for Bech32 string.
 * @param[in]  hrp_len
 *   Lenght of `hrp` string.
 * @param[in]  in
 *   Pointer to input byte buffer.
 * @param[in]  in_len
 *   Length of input byte buffer.
 * @param[out] dst
 *   Pointer to output byte buffer.
 * @param[in,out] dst_len
 *   Pointer to lenght of output byte buffer, will be set to actual length.
 *
 * @return true if success, false otherwise.
 *
 */
bool abstract_addr_from_bytes(char *hrp,
                              size_t hrp_len,

                              const uint8_t *in,
                              size_t in_len,

                              char *dst,
                              size_t *dst_len);