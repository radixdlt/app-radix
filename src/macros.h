#pragma once

#include "sw.h"
#include "os.h"

// MACROS
#define PLOC() PRINTF("\n%s - %s:%d \n", __FILE__, __func__, __LINE__);

#define FATAL_ERROR(...)     \
    {                        \
        PLOC();              \
        PRINTF(__VA_ARGS__); \
        THROW(SW_BAD_STATE); \
    }

#define ASSERT(x, msg)    \
    if (x) {              \
    } else {              \
        FATAL_ERROR(msg); \
    }