/*****************************************************************************
 *   (c) 2020 Ledger SAS.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *****************************************************************************/

#include <stdint.h>   // uint*_t
#include <stddef.h>   // size_t
#include <stdbool.h>  // bool
#include <string.h>   // memmove

#include "buffer.h"
#include "read.h"
#include "os.h"

size_t number_of_remaining_bytes_in_buffer(const buffer_t *buffer) {
    return buffer->size - buffer->offset;
}

bool buffer_can_read(const buffer_t *buffer, size_t n) {
    return buffer->size - buffer->offset >= n;
}

bool buffer_seek_set(buffer_t *buffer, size_t offset) {
    if (offset > buffer->size) {
        return false;
    }

    buffer->offset = offset;

    return true;
}

bool buffer_seek_cur(buffer_t *buffer, size_t offset) {
    if (buffer->offset + offset < buffer->offset) {
        // overflow
        PRINTF("`buffer_seek_cur` failed, because of overflow.\n");
        return false;
    }
    if (buffer->offset + offset > buffer->size) {
        // exceed buffer size
        PRINTF("`buffer_seek_cur` failed, because buffer size exceeded.\n");
        return false;
    }

    buffer->offset += offset;

    return true;
}

bool buffer_seek_end(buffer_t *buffer, size_t offset) {
    if (offset > buffer->size) {
        return false;
    }

    buffer->offset = buffer->size - offset;

    return true;
}

bool buffer_read_u8(buffer_t *buffer, uint8_t *value) {
    if (!buffer_can_read(buffer, 1)) {
        *value = 0;

        return false;
    }

    *value = buffer->ptr[buffer->offset];
    buffer_seek_cur(buffer, 1);

    return true;
}

bool buffer_read_u16(buffer_t *buffer, uint16_t *value, endianness_t endianness) {
    if (!buffer_can_read(buffer, 2)) {
        *value = 0;

        return false;
    }

    *value = ((endianness == BE) ? read_u16_be(buffer->ptr, buffer->offset)
                                 : read_u16_le(buffer->ptr, buffer->offset));

    buffer_seek_cur(buffer, 2);

    return true;
}

bool buffer_read_u32(buffer_t *buffer, uint32_t *value, endianness_t endianness) {
    if (!buffer_can_read(buffer, 4)) {
        *value = 0;

        return false;
    }

    *value = ((endianness == BE) ? read_u32_be(buffer->ptr, buffer->offset)
                                 : read_u32_le(buffer->ptr, buffer->offset));

    buffer_seek_cur(buffer, 4);

    return true;
}

bool buffer_read_u64(buffer_t *buffer, uint64_t *value, endianness_t endianness) {
    if (!buffer_can_read(buffer, 8)) {
        *value = 0;

        return false;
    }

    *value = ((endianness == BE) ? read_u64_be(buffer->ptr, buffer->offset)
                                 : read_u64_le(buffer->ptr, buffer->offset));

    buffer_seek_cur(buffer, 8);

    return true;
}

bool buffer_read_bip32_path(buffer_t *buffer, bip32_path_t *target) {
    if (!bip32_path_read(buffer->ptr + buffer->offset, buffer->size - buffer->offset, target)) {
        return false;
    }

    buffer_seek_cur(buffer, sizeof(*target->path) * target->path_len);

    return true;
}

bool buffer_copy_some(const buffer_t *buffer,
                      uint8_t *out,
                      const size_t out_len,
                      const size_t bytes_to_copy_count) {
    size_t remaining_byte_count = number_of_remaining_bytes_in_buffer(buffer);
    if (bytes_to_copy_count > out_len) {
        PRINTF(
            "'buffer_copy_some' is failing, because `bytes_to_copy_count`: %d, is larger than "
            "`out_len`: %d.\n",
            bytes_to_copy_count,
            out_len);
        debug_print_buffer(buffer);
        return false;
    }

    if (bytes_to_copy_count > remaining_byte_count) {
        PRINTF(
            "'buffer_copy_some' is failing, because `bytes_to_copy_count`: %d, is larger than "
            "`remaining_byte_count`: %d.\n",
            bytes_to_copy_count,
            remaining_byte_count);
        debug_print_buffer(buffer);
        return false;
    }

    memmove(out, buffer->ptr + buffer->offset, remaining_byte_count);

    return true;
}

bool buffer_copy_remaining(const buffer_t *buffer, uint8_t *out, const size_t out_len) {
    return buffer_copy_some(buffer, out, out_len, number_of_remaining_bytes_in_buffer(buffer));
}

bool buffer_copy_fill_target(const buffer_t *buffer, uint8_t *target, const size_t target_len) {
    return buffer_copy_some(buffer, target, target_len, target_len);
}

bool buffer_move_some(buffer_t *buffer,
                      uint8_t *out,
                      const size_t out_len,
                      const size_t bytes_to_move_count) {
    if (!buffer_copy_some(buffer, out, out_len, bytes_to_move_count)) {
        PRINTF("'buffer_move_some' is failing, because `buffer_copy_some` is failing.\n");
        return false;
    }

    if (!buffer_seek_cur(buffer, bytes_to_move_count)) {
        PRINTF("'buffer_move_some' is failing, because `buffer_seek_cur` is failing\n.");
        return false;
    }

    return true;
}

bool buffer_move_fill_target(buffer_t *buffer, uint8_t *target, const size_t target_len) {
    return buffer_move_some(buffer, target, target_len, target_len);
}

void debug_print_buffer(const buffer_t *buffer) {
    size_t remaining_byte_count = number_of_remaining_bytes_in_buffer(buffer);
    UNUSED(remaining_byte_count);  // If debug build 'remaining_byte_count' is considered unused.
    PRINTF("\n\n~~~ BUFFER ~~~\n");

    PRINTF("Size: #%d bytes\n", buffer->size);
    PRINTF("Offset: @%d\n", buffer->offset);
    PRINTF("Bytes left: #%d bytes\n", remaining_byte_count);

    PRINTF("Remaining bytes: %.*h\n", remaining_byte_count, (buffer->ptr + buffer->offset));
    PRINTF("~~~ END ~~~\n\n\n");
}
