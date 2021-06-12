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