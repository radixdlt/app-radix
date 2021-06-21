#pragma once

#include "sw.h"
#include "os.h"

// MACROS

#define FATAL_ERROR(...)        \
    {                           \
        PRINTF(__VA_ARGS__);    \
        THROW(ERR_FATAL_ERROR); \
    }

#define ASSERT(x, msg)               \
    if (x) {                         \
    } else {                         \
        THROW(ERR_ASSERTION_FAILED); \
    }

/**
 * Macro for the size of a specific structure field.
 */
#define MEMBER_SIZE(type, member) (sizeof(((type *) 0)->member))
