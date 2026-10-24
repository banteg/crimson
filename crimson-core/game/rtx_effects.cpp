// Analytic presentation primitives, shared with render/rtx/effects.py and
// effect.frag. Hooks replace selected world draws only; no effect/projectile
// fields are written.
#include "crimsonland_gameplay.h"
#include "grim2d_cpp.h"
#include "host_abi.h"
#include <algorithm>
#include <math.h>

extern IGrim2D_cpp *grim_interface_ptr;
extern "C" {
extern vec2f_t camera_offset;
extern int particles_texture;
extern unsigned long grim_color_slot0[4];
extern float grim_uv_u0[8];
extern float grim_rotation_radians;
extern unsigned char portable_preserve_bugs;
bool rtx_drawing();
int rtx_effects_active;
}

namespace {
enum { WARM, AURA, RING, PLASMA, ARC };
int bound_texture = -1;
float byte_alpha(float a) {
  return floorf(std::clamp(a, 0.f, 1.f) * 255.f + .5f) / 255.f;
}
unsigned rgba(float r, float g, float b, float a) {
  return (unsigned)(byte_alpha(a) * 255) << 24 |
         (unsigned)(byte_alpha(r) * 255) << 16 |
         (unsigned)(byte_alpha(g) * 255) << 8 | (unsigned)(byte_alpha(b) * 255);
}
void emit(int kind, float cx, float cy, float ax, float ay, float x0, float y0,
          float x1, float y1, float u0, float v0, float u1, float v1,
          const float *params, unsigned color) {
  const float corners[16] = {
      cx + ax * x0 - ay * y0, cy + ay * x0 + ax * y0, u0, v0,
      cx + ax * x0 - ay * y1, cy + ay * x0 + ax * y1, u0, v1,
      cx + ax * x1 - ay * y1, cy + ay * x1 + ax * y1, u1, v1,
      cx + ax * x1 - ay * y0, cy + ay * x1 + ax * y0, u1, v0};
  grim_interface_ptr->grim_flush_batch();
  host_effect(corners, kind, params, color);
}
void sprite(int kind, float cx, float cy, float w, float h, float angle,
            unsigned color) {
  if (w <= 0 || h <= 0 || !(color >> 24))
    return;
  const float params[12] = {};
  emit(kind, cx, cy, cosf(angle), sinf(angle), -w * .5f, -h * .5f, w * .5f,
       h * .5f, -1, -1, 1, 1, params, color);
}
int effect_kind(int id) {
  return id == 13 ? WARM : id == 16 ? AURA : id == 1 ? RING : -1;
}
bool drawing() { return rtx_effects_active && rtx_drawing(); }
} // namespace

extern "C" void rtx_effect_texture(int handle, int stage) {
  if (stage == 0)
    bound_texture = handle;
}

// The sprite methods keep their normal state/UV bookkeeping. Only whole known
// cells on particles are intercepted, so other atlases and UI draws cannot
// match.
extern "C" bool rtx_effect_quad(float x, float y, float w, float h) {
  if (!drawing() || bound_texture != particles_texture)
    return false;
  for (int i = 1; i < 4; ++i)
    if (grim_color_slot0[i] != grim_color_slot0[0])
      return false;
  float u0 = grim_uv_u0[0], v0 = grim_uv_u0[1], u1 = grim_uv_u0[4],
        v1 = grim_uv_u0[5];
  int kind = -1;
  if (u0 == .75f && v0 == 0 && u1 == 1 && v1 == .25f)
    kind = WARM;
  if (u0 == .5f && v0 == .25f && u1 == .75f && v1 == .5f)
    kind = AURA;
  if (u0 == .5f && v0 == .5f && u1 == 1 && v1 == 1)
    kind = RING;
  if (kind < 0)
    return false;
  // Ensure the other two corners are a whole rectangular cell as well.
  if (grim_uv_u0[2] != u1 || grim_uv_u0[3] != v0 || grim_uv_u0[6] != u0 ||
      grim_uv_u0[7] != v1)
    return false;
  sprite(kind, x + w * .5f, y + h * .5f, w, h, grim_rotation_radians,
         (unsigned)grim_color_slot0[0]);
  return true;
}

extern "C" bool rtx_effect_entry(const effect_entry_t *e) {
  int kind = effect_kind(e->effect_id);
  if (!drawing() || kind < 0)
    return false;
  sprite(
      kind, camera_offset.x + e->pos_x, camera_offset.y + e->pos_y,
      e->half_width * 2 * e->scale, e->half_height * 2 * e->scale, e->rotation,
      // Native effect entries truncate their byte colors, unlike set_color.
      (unsigned)(e->color.a * 255) << 24 | (unsigned)(e->color.r * 255) << 16 |
          (unsigned)(e->color.g * 255) << 8 | (unsigned)(e->color.b * 255));
  return true;
}

extern "C" void rtx_plasma(int slot, float alpha) {
  const projectile_t &p = projectile_pool[slot];
  int type = p.fields.type_id;
  float cx = camera_offset.x + p.fields.pos_x,
        cy = camera_offset.y + p.fields.pos_y;
  if (p.fields.life_timer < .4f) {
    sprite(WARM, cx, cy, 56, 56, 0,
           rgba(1, 1, 1,
                std::clamp(p.fields.life_timer * 2.5f, 0.f, 1.f) * alpha));
    return;
  }
  float r = 1, g = 1, b = 1, divisor = 2.1f, step_factor = 2.1f, tail = 6,
        head = 8, head_a = .5f, aura = 60, aura_a = .15f;
  int cap = 3;
  if (type == PROJECTILE_TYPE_PLASMA_RIFLE) {
    divisor = step_factor = 2.5f;
    cap = 8;
    tail = 11;
    head = 28;
    head_a = .45f;
    aura = 128;
    aura_a = .3f;
  } else if (type == PROJECTILE_TYPE_PLASMA_CANNON) {
    divisor = 3.5f;
    step_factor = 2.6f;
    cap = 18;
    tail = 22;
    head = 42;
    head_a = .45f;
    aura = 128;
    aura_a = .4f;
  } else if (type == PROJECTILE_TYPE_SPIDER_PLASMA) {
    r = .3f;
    b = .3f;
  } else if (type == PROJECTILE_TYPE_SHRINKIFIER) {
    r = .3f;
    g = .3f;
  }
  float dx = p.fields.pos_x - p.fields.origin_x,
        dy = p.fields.pos_y - p.fields.origin_y;
  int divisor_i = (int)(p.fields.speed_scale * divisor);
  int count = divisor_i > 0
                  ? std::min((int)sqrtf(dx * dx + dy * dy) / divisor_i, cap)
                  : 0;
  float step = p.fields.speed_scale * step_factor;
  if (step <= 0) {
    step = 1;
    count = 0;
  }
  if (!config_blob.flame_glow_enabled) {
    aura = 0;
    aura_a = 0;
  }
  float ax = cosf(p.angle - 1.5707964f), ay = sinf(p.angle - 1.5707964f);
  float params[12] = {tail,
                      head,
                      aura,
                      count * step,
                      step,
                      byte_alpha(alpha * .4f),
                      byte_alpha(alpha * head_a),
                      byte_alpha(alpha * aura_a),
                      .027944f * ax + .036952f * ay,
                      -.027944f * ay + .036952f * ax,
                      0,
                      0};
  float radius = std::max({tail, head, aura}),
        back = std::max(0.f, (count - .5f) * step);
  emit(PLASMA, cx, cy, ax, ay, -back - radius, -radius, radius + step * .5f,
       radius, -back - radius, -radius, radius + step * .5f, radius, params,
       rgba(r, g, b, 1));
}

extern "C" void rtx_ion_arc(float sx, float sy, float ex, float ey, float scale,
                            float alpha) {
  float ax = ex - sx, ay = ey - sy, len = sqrtf(ax * ax + ay * ay);
  if (len <= 1e-3f)
    return;
  ax /= len;
  ay /= len;
  float radius = 16 * scale;
  const float params[12] = {
      len, scale, portable_preserve_bugs ? 0.f : 1.f, 0, 0, 0, 0, 0, 0, 0,
      0,   0};
  emit(ARC, sx, sy, ax, ay, -radius, -radius, len + radius, radius, -radius,
       -radius, len + radius, radius, params, rgba(.5f, .6f, 1, alpha));
}
