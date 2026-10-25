#pragma once
#include <stdint.h>

// The existing device vertex layout, so analytic sprite batches carry their own
// tints.
struct EffectVertex {
  float x, y, z, rhw;
  uint32_t color;
  float u, v;
};
static_assert(sizeof(EffectVertex) == 28);
inline void effect_quad(const float *corners, uint32_t color,
                        EffectVertex *vertices) {
  const int order[6] = {0, 1, 2, 0, 2, 3};
  for (int i = 0; i < 6; ++i) {
    const float *c = corners + order[i] * 4;
    vertices[i] = {c[0], c[1], 0, 1, color, c[2], c[3]};
  }
}
