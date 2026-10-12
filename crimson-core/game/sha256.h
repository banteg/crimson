#pragma once
#include <stddef.h>
#include <stdint.h>

void sha256(const void *data, size_t size, uint8_t digest[32]);
