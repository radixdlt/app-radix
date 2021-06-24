#pragma once

#include <stdint.h>
#include <stddef.h>

// FROM: https://gist.github.com/vi/dd3b5569af8a26b97c8e20ae06e804cb
void hex_to_bin(const char *str, uint8_t *bytes, size_t blen);