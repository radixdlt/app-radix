#pragma once

#include <stdint.h>   // uint*_t
#include <stddef.h>   // size_t
#include <stdbool.h>  // bool

#define XRD_HRP "xrd"

bool rri_system(uint8_t byte, char *out, size_t *out_len);
bool rri_(char *out, size_t *out_len);
