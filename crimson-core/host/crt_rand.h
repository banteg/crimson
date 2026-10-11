#pragma once
#include <stdint.h>
// The original's rand(): the C runtime's linear congruential stream.
extern "C" uint32_t *crt_rand_stream(); // the stream crt_rand draws from now (host.cpp)
static constexpr uint32_t crt_rand_multiplier = 214013u;
static constexpr uint32_t crt_rand_increment = 2531011u;
static inline int crt_rand_step(uint32_t *state) {
  *state = *state * crt_rand_multiplier + crt_rand_increment;
  return (*state >> 16) & 0x7fff;
}

// The stream n draws on is a multiply and an add away, so a draw whose place is
// known reads from the first state without the draws before it.
struct rand_jump_t {
  uint32_t mul, add;
};
static constexpr rand_jump_t rand_jump(int n) {
  rand_jump_t jump = {1, 0};
  for (int i = 0; i < n; ++i) {
    jump.mul *= crt_rand_multiplier;
    jump.add = jump.add * crt_rand_multiplier + crt_rand_increment;
  }
  return jump;
}
template <int N> static inline uint32_t rand_ahead(uint32_t state) {
  constexpr rand_jump_t jump = rand_jump(N);
  return state * jump.mul + jump.add;
}
template <int N> static inline int rand_draw(uint32_t state) {
  return (rand_ahead<N>(state) >> 16) & 0x7fff;
}
