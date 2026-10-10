#pragma once
#include <stdint.h>
// The original's rand(): the C runtime's linear congruential stream.
extern "C" uint32_t *crt_rand_stream(); // the stream crt_rand draws from now (host.cpp)
static inline int crt_rand_step(uint32_t *state) {
  *state = *state * 214013u + 2531011u;
  return (*state >> 16) & 0x7fff;
}
