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
#include "../game/render_passes.h"
// The material host_bonus starts, beside the lit passes, until the next pass.
enum { MATERIAL_BONUS = HOST_PASS_ICE_SHARDS + 1 };
// Each device vertex's quad center (x, y), the mean of its quad's vertices: Grim
// batches quads as four consecutive vertices. The RTX creature lighting spares
// that creature's own body (creature_lit.vert).
inline void quad_centers(const float *vertices, unsigned count, float *centers) {
  for (unsigned first = 0; first < count; first += 4) {
    unsigned corners = count - first < 4 ? count - first : 4;
    float x = 0, y = 0;
    for (unsigned v = first; v < first + corners; ++v)
      x += vertices[v * 7], y += vertices[v * 7 + 1];
    for (unsigned v = first; v < first + corners; ++v)
      centers[v * 2] = x / corners, centers[v * 2 + 1] = y / corners;
  }
}
