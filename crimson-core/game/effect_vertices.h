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
// A circle's square (host_circle: center x and y, inner and outer radius, the texture's u and its v at the inner
// and outer edges) with two pixels to spare for its edge, and classic.frag's circle and circle_uv for it.
inline void circle_quad(const float *shape, uint32_t color, EffectVertex *vertices, float *uniforms) {
  float reach = shape[3] + 2;
  for (int i = 0; i < 4; ++i)
    vertices[i] = {shape[0] + (i == 1 || i == 2 ? reach : -reach), shape[1] + (i < 2 ? -reach : reach), 0, 1, color,
                   shape[4], shape[5]};
  for (int i = 0; i < 7; ++i)
    uniforms[i] = shape[i];
  uniforms[7] = 0;
}
inline void effect_quad(const float *corners, uint32_t color,
                        EffectVertex *vertices) {
  const int order[6] = {0, 1, 2, 0, 2, 3};
  for (int i = 0; i < 6; ++i) {
    const float *c = corners + order[i] * 4;
    vertices[i] = {c[0], c[1], 0, 1, color, c[2], c[3]};
  }
}
