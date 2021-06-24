#include "hasher.h"

#include <string.h>
#include "../bridge.h"  // PRINTF

void init_hasher(hasher_t* hasher,
                 sha_256_once_fn sha_256_once,
                 init_implementing_hasher_fn init_implementing_hasher) {
    explicit_bzero(hasher, sizeof(*hasher));
    init_implementing_hasher();
    hasher->sha_256_once = sha_256_once;
    hasher->reinit_implementing_hasher = init_implementing_hasher;
}

bool update_hash(hasher_t* hasher, buffer_t* buffer, bool finalize) {
    sha_256_once_fn sha_256_once = hasher->sha_256_once;
    return sha_256_once(buffer, finalize, hasher->hash);
}

bool update_hash_twice(hasher_t* hasher, buffer_t* buffer, bool finalize) {
    if (!update_hash(hasher, buffer, finalize)) {
        return false;
    }

    if (finalize) {
        init_implementing_hasher_fn reinit_implementing_hasher = hasher->reinit_implementing_hasher;
        // Prepare implementing hasher for a second pass.
        reinit_implementing_hasher();

        // tmp copy of firstHash
        uint8_t hashed_once[HASH_LEN];
        memmove(hashed_once, hasher->hash, HASH_LEN);
        buffer_t second_buf = (buffer_t){
            .offset = 0,
            .ptr = hashed_once,
            .size = HASH_LEN,
        };

        if (!update_hash(hasher, &second_buf, true)) {
            return false;
        }

        PRINTF("Finalized hash to: '%.*h'\n", HASH_LEN, hasher->hash);
    }

    return true;
}
