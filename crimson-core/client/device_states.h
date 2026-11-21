#pragma once
// The Direct3D 8 render and texture stage states the game module's device forwards
// (game/host_abi.h), which both renderers interpret.
enum {
  RS_ALPHATESTENABLE = 15,
  RS_SRCBLEND = 19,
  RS_DESTBLEND = 20,
  RS_CULLMODE = 22,
  RS_ALPHAREF = 24,
  RS_ALPHAFUNC = 25,
  RS_ALPHABLENDENABLE = 27,
  RS_TEXTUREFACTOR = 60,
  RS_COLORWRITEENABLE = 168,
  RS_BLENDOP = 171,
  TSS_COLOROP = 1,
  TSS_COLORARG1 = 2,
  TSS_COLORARG2 = 3,
  TSS_ALPHAOP = 4,
  TSS_ALPHAARG1 = 5,
  TSS_ALPHAARG2 = 6,
  TSS_ADDRESSU = 13,
  TSS_ADDRESSV = 14,
  TSS_MAGFILTER = 16,
  TSS_MINFILTER = 17,
  // Host extension: the platform identifies terrain artwork by its Grim slot.
  TSS_TERRAIN_ART = 31,
  STAGES = 2,
};
// Target flags: host_texture_create's (1 render target, 2 no alpha) and the host's
// own half-float storage, which the RTX back buffer and world target use, and
// float storage, the RTX ground's surface.
enum { TARGET_RENDER = 1, TARGET_OPAQUE = 2, TARGET_HALF_FLOAT = 4, TARGET_FLOAT = 8 };
// Only additive emission may bypass the art's coverage cutoff in linear light,
// and only where its alpha scales what it adds (SRCALPHA, ONE): there the cutoff
// was a step, and below it the light fades on. A (ONE, ONE) draw adds its color
// whatever its alpha, so the test is all that hides it: the muzzle flash draws
// every frame at alpha 0. Keep those, and opaque, alpha-composited, subtractive
// and mask draws, on their native test.
inline bool additive_emission(const unsigned *states) {
  return states[RS_ALPHABLENDENABLE] && states[RS_BLENDOP] == 1 &&
         states[RS_DESTBLEND] == 2 && states[RS_SRCBLEND] == 5;
}
#include "../game/render_passes.h"
// The material host_bonus starts, beside the lit passes, until the next pass.
enum { MATERIAL_BONUS = HOST_PASS_GLINT + 1 };
// Each device vertex's quad center (x, y), the mean of its quad's vertices: Grim
// batches quads as four consecutive vertices. The RTX creature lighting spares
// that creature's own body (creature_lit.vert).
inline void quad_centers(const float *vertices, unsigned count, float *centers, bool strip = false) {
  for (unsigned first = 0; first < count; first += 4) {
    unsigned corners = count - first < 4 ? count - first : 4;
    float x = 0, y = 0;
    for (unsigned v = first; v < first + corners; ++v)
      x += vertices[v * 7], y += vertices[v * 7 + 1];
    float cx = x / corners, cy = y / corners;
    // Align d00 with the shared diagonal (v0-v2 for quad lists, v1-v2 for 4-vertex strips)
    // and d01 with triangle 0's off-diagonal corner (v1 for quad lists, v0 for strips), so
    // triangle 0 is always (c00, c01, c11) and triangle 1 is always (c00, c11, c10).
    unsigned i0 = strip && corners >= 4 ? first + 1 : first;
    unsigned i1 = strip && corners >= 4 ? first : first + 1;
    float d0x = vertices[i0 * 7] - cx, d0y = vertices[i0 * 7 + 1] - cy;
    float d1x = corners >= 4 ? vertices[i1 * 7] - cx : d0y;
    float d1y = corners >= 4 ? vertices[i1 * 7 + 1] - cy : -d0x;
    for (unsigned v = first; v < first + corners; ++v) {
      centers[v * 6] = cx, centers[v * 6 + 1] = cy;
      centers[v * 6 + 2] = d0x, centers[v * 6 + 3] = d0y;
      centers[v * 6 + 4] = d1x, centers[v * 6 + 5] = d1y;
    }
  }
}
