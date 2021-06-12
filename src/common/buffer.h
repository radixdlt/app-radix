#pragma once

#include <stdint.h>   // uint*_t
#include <stddef.h>   // size_t
#include <stdbool.h>  // bool

/**
 * Enumeration for endianness.
 */
typedef enum {
    BE,  /// Big Endian
    LE   /// Little Endian
} endianness_t;

/**
 * Struct for buffer with size and offset.
 */
typedef struct {
    const uint8_t *ptr;  /// Pointer to byte buffer
    size_t size;         /// Size of byte buffer
    size_t offset;       /// Offset in byte buffer
} buffer_t;

void debug_print_buffer(const buffer_t *buffer);

/**
 * Tell whether buffer can read bytes or not.
 *
 * @param[in] buffer
 *   Pointer to input buffer struct.
 * @param[in] n
 *   Number of bytes to read in buffer.
 *
 * @return true if success, false otherwise.
 *
 */
bool buffer_can_read(const buffer_t *buffer, size_t n);

/**
 * Seek the buffer to specific offset.
 *
 * @param[in,out] buffer
 *   Pointer to input buffer struct.
 * @param[in]     offset
 *   Specific offset to seek.
 *
 * @return true if success, false otherwise.
 *
 */
bool buffer_seek_set(buffer_t *buffer, size_t offset);

/**
 * Seek buffer relatively to current offset.
 *
 * @param[in,out] buffer
 *   Pointer to input buffer struct.
 * @param[in]     offset
 *   Offset to seek relatively to `buffer->offset`.
 *
 * @return true if success, false otherwise.
 *
 */
bool buffer_seek_cur(buffer_t *buffer, size_t offset);

/**
 * Seek the buffer relatively to the end.
 *
 * @param[in,out] buffer
 *   Pointer to input buffer struct.
 * @param[in]     offset
 *   Offset to seek relatively to `buffer->size`.
 *
 * @return true if success, false otherwise.
 *
 */
bool buffer_seek_end(buffer_t *buffer, size_t offset);

/**
 * Read 1 byte from buffer into uint8_t.
 *
 * @param[in,out]  buffer
 *   Pointer to input buffer struct.
 * @param[out]     value
 *   Pointer to 8-bit unsigned integer read from buffer.
 *
 * @return true if success, false otherwise.
 *
 */
bool buffer_read_u8(buffer_t *buffer, uint8_t *value);

/**
 * Read 2 bytes from buffer into uint16_t.
 *
 * @param[in,out]  buffer
 *   Pointer to input buffer struct.
 * @param[out]     value
 *   Pointer to 16-bit unsigned integer read from buffer.
 * @param[in]      endianness
 *   Either BE (Big Endian) or LE (Little Endian).
 *
 * @return true if success, false otherwise.
 *
 */
bool buffer_read_u16(buffer_t *buffer, uint16_t *value, endianness_t endianness);

/**
 * Read 4 bytes from buffer into uint32_t.
 *
 * @param[in,out]  buffer
 *   Pointer to input buffer struct.
 * @param[out]     value
 *   Pointer to 32-bit unsigned integer read from buffer.
 * @param[in]      endianness
 *   Either BE (Big Endian) or LE (Little Endian).
 *
 * @return true if success, false otherwise.
 *
 */
bool buffer_read_u32(buffer_t *buffer, uint32_t *value, endianness_t endianness);

/**
 * Read 8 bytes from buffer into uint64_t.
 *
 * @param[in,out]  buffer
 *   Pointer to input buffer struct.
 * @param[out]     value
 *   Pointer to 64-bit unsigned integer read from buffer.
 * @param[in]      endianness
 *   Either BE (Big Endian) or LE (Little Endian).
 *
 * @return true if success, false otherwise.
 *
 */
bool buffer_read_u64(buffer_t *buffer, uint64_t *value, endianness_t endianness);


/**
 * Read BIP32 path from buffer.
 *
 * @param[in,out]  buffer
 *   Pointer to input buffer struct.
 * @param[out]     out
 *   Pointer to output 32-bit integer buffer.
 * @param[in]      out_len
 *   Number of BIP32 paths read in the output buffer.
 *
 * @return true if success, false otherwise.
 *
 */
bool buffer_read_bip32_path(buffer_t *buffer, uint32_t *out, size_t out_len);

/**
 * Copy \p bytes_to_copy_count bytes from \p buffer without moving offset.
 *
 * @param[in]  buffer
 *   Pointer to input buffer struct.
 * @param[out] out
 *   Pointer to output byte buffer.
 * @param[in]  out_len
 *   Length of output byte buffer.
 *  @param[in]  bytes_to_copy_count
 *   Number of bytes to copy.
 *
 * @return true if success, false otherwise.
 *
 */
bool buffer_copy_some(const buffer_t *buffer,
                      uint8_t *out,
                      const size_t out_len,
                      const size_t bytes_to_copy_count);

/**
 * Copy all bytes from \p buffer without moving offset.
 *
 * @param[in]  buffer
 *   Pointer to input buffer struct.
 * @param[out] target
 *   Pointer to target output byte buffer to fill with bytes from \p buffer.
 * @param[in]  target_len
 *   Length of target output byte buffer.
 *
 * @return true if success, false otherwise.
 *
 */
bool buffer_copy_fill_target(const buffer_t *buffer, uint8_t *target, const size_t target_len);

/**
 * @brief Copies the remaining bytes from \p buffer to \p out output buffer.
 *
 * @param buffer
 * @param out
 * @param out_len
 * @return true if success, false otherwise.
 */
bool buffer_copy_remaining(const buffer_t *buffer, uint8_t *out, const size_t out_len);

size_t number_of_remaining_bytes_in_buffer(const buffer_t *buffer);

/**
 * Move bytes from buffer.
 *
 * \p out_len must be >= \p bytes_to_move_count, and number of remaining bytes in \p buffer must be
 * >= \p bytes_to_move_count. You can use method \code number_of_remaining_bytes_in_buffer to get
 * number of remaining bytes.
 *
 * It is also useful to \code debug_print_buffer.
 *
 * @param[in,out]  buffer
 *   Pointer to input buffer struct.
 * @param[out]     out
 *   Pointer to output byte buffer.
 * @param[in]  out_len
 *   Length of output byte buffer.
 * @param[in]      bytes_to_move_count
 *   Numberf of bytes to move.
 *
 * @return true if success, false otherwise.
 *
 */
bool buffer_move_some(buffer_t *buffer,
                      uint8_t *out,
                      const size_t out_len,
                      const size_t bytes_to_move_count);

/**
 * Move bytes from \p buffer to fill \p target.
 *
 * @param[in,out]  buffer
 *   Pointer to input buffer struct.
 * @param[out]     target
 *   Pointer to target output byte buffer.
 * @param[in]  target_len
 *   Length of target output byte buffer.
 *
 * @return true if success, false otherwise.
 *
 */
bool buffer_move_fill_target(buffer_t *buffer, uint8_t *target, const size_t target_len);
