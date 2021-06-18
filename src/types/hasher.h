#pragma once

#include <stdbool.h>
#include <stdint.h>
#include "../constants.h"
#include "buffer.h"

typedef bool (*sha_256_once_fn)(buffer_t*, bool, uint8_t*);

// Used to re-init an implementing hasher, called before performing a second update hash pass (e.g.
// when doing SHA256(SHA256)).
typedef void (*init_implementing_hasher_fn)(void);

typedef struct {
    uint8_t hash[HASH_LEN];
    sha_256_once_fn sha_256_once;
    init_implementing_hasher_fn reinit_implementing_hasher;
} hasher_t;

void init_hasher(hasher_t* hasher,
                 sha_256_once_fn sha_256_once,
                 init_implementing_hasher_fn init_implementing_hasher);

bool update_hash(hasher_t* hasher, buffer_t* buffer, bool finalize);

bool update_hash_twice(hasher_t* hasher, buffer_t* buffer, bool finalize);