// Analytic presentation primitives, shared with render/rtx/effects.py and
// effect.frag. Hooks replace selected world draws only; no effect/projectile
// fields are written.
#include "crimsonland_gameplay.h"
#include "effect_vertices.h"
#include "grim2d_cpp.h"
#include "host_abi.h"
#include <algorithm>
#include <math.h>
#include <vector>

extern IGrim2D_cpp *grim_interface_ptr;
extern "C" {
extern vec2f_t camera_offset;
extern int particles_texture;
extern int grim_bound_texture_handle;
extern grim_config_value_t grim_config_values[128];
extern unsigned long grim_color_slot0[4];
extern float grim_uv_u0[8];
extern unsigned int grim_vertex_count;
extern unsigned char portable_preserve_bugs;
extern float effect_uv_step_2, effect_uv_step_4, effect_uv_step_8, effect_uv_step_16;
bool rtx_drawing();
int rtx_effects_active;
}

namespace {
enum { WARM, AURA, RING, PLASMA, ARC, PULSE, BURST };
std::vector<EffectVertex> sprite_vertices;
int sprite_kind = -1;
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
bool drawing() { return rtx_effects_active && rtx_drawing(); }
bool additive() {
  return grim_config_values[0x12].words[0] &&
         grim_config_values[0x13].words[0] == 5 &&
         grim_config_values[0x14].words[0] == 2;
}
} // namespace

// The sprite methods keep their normal state/UV bookkeeping. Only whole known
// cells on particles are intercepted, so other atlases and UI draws cannot
// match.
extern "C" void rtx_effect_flush() {
  if (!sprite_vertices.empty()) {
    if (drawing())
      host_effect_sprites(sprite_vertices.data(), sprite_kind,
                          (int)sprite_vertices.size());
    sprite_vertices.clear();
  }
}

namespace {
int sprite_cell(const EffectVertex *v) {
  // Each rectangle as effect_spawn builds it from the original effect atlas and
  // UV tables, rather than maintaining UV copies: the 2x2 cells' step stops two
  // texels short of the next cell.
  const struct {
    int id, kind;
  } cells[] = {{13, WARM}, {16, AURA}, {1, RING}, {0, BURST}};
  for (const auto &cell : cells) {
    const auto &entry = effect_id_table[cell.id];
    const uv2f_t *table = entry.size_code == 0x10   ? effect_uv16
                          : entry.size_code == 0x20 ? effect_uv8
                          : entry.size_code == 0x40 ? effect_uv4
                                                    : effect_uv2;
    float step = entry.size_code == 0x10   ? effect_uv_step_16
                 : entry.size_code == 0x20 ? effect_uv_step_8
                 : entry.size_code == 0x40 ? effect_uv_step_4
                                           : effect_uv_step_2;
    auto matches = [&](float u, float w, float size) {
      return v[0].u == u && v[0].v == w && v[1].u == u + size && v[1].v == w &&
             v[2].u == u + size && v[2].v == w + size && v[3].u == u && v[3].v == w + size;
    };
    // Retained explosion shells use effect_select_texture / grim_set_atlas_frame,
    // whose immediate quads cover the full cell rather than effect_spawn's inset.
    int grid = 256 / entry.size_code;
    float unit = 1.f / grid;
    if (matches(table[entry.frame].u, table[entry.frame].v, step) ||
        matches((entry.frame % grid) * unit, (entry.frame / grid) * unit, unit))
      return cell.kind;
  }
  return -1;
}
void enqueue(int kind, const EffectVertex *quad) {
  // Flush earlier textured work first. The hook in Grim's flush preserves
  // ordering with all later artwork, blend/texture changes, target changes and
  // frame boundaries.
  if ((grim_vertex_count & 0xffff) != 0)
    grim_interface_ptr->grim_flush_batch();
  if (kind != sprite_kind || sprite_vertices.size() >= 6 * 256)
    rtx_effect_flush();
  sprite_kind = kind;
  const int order[6] = {0, 1, 2, 0, 2, 3};
  for (int i : order)
    sprite_vertices.push_back(quad[i]);
}
// A radial sprite's corners span -1..1 of its shape.
void radial(EffectVertex (&quad)[4]) {
  for (int i = 0; i < 4; ++i) {
    quad[i].u = (i == 1 || i == 2) ? 1.f : -1.f;
    quad[i].v = i >= 2 ? 1.f : -1.f;
  }
}
void sprite(int kind, float cx, float cy, float w, float h, float angle,
            unsigned color) {
  if (w <= 0 || h <= 0 || !(color >> 24))
    return;
  EffectVertex quad[4];
  const float xy[8] = {-1, -1, 1, -1, 1, 1, -1, 1};
  float co = cosf(angle), si = sinf(angle);
  for (int i = 0; i < 4; ++i) {
    float x = xy[2 * i] * w * .5f, y = xy[2 * i + 1] * h * .5f;
    quad[i] = {cx + co * x - si * y, cy + si * x + co * y, 0, 1, color, 0, 0};
  }
  radial(quad);
  enqueue(kind, quad);
}
} // namespace

extern "C" bool rtx_effect_vertices(const void *vertices, int count) {
  if (!drawing() || count != 4 ||
      grim_bound_texture_handle != particles_texture)
    return false;
  const auto *v = (const EffectVertex *)vertices;
  int kind = sprite_cell(v);
  if (kind < 0 || ((kind == WARM || kind == BURST) && !additive()))
    return false;
  // The source can be Grim's mapped buffer, which a flush may relock.
  EffectVertex quad[4];
  std::copy(v, v + 4, quad);
  radial(quad);
  enqueue(kind, quad);
  return true;
}

extern "C" bool rtx_effect_quad(const float *points) {
  if (!drawing() || grim_bound_texture_handle != particles_texture)
    return false;
  EffectVertex quad[4];
  for (int i = 0; i < 4; ++i)
    quad[i] = {points[2 * i],
               points[2 * i + 1],
               0,
               1,
               (uint32_t)grim_color_slot0[i],
               grim_uv_u0[2 * i],
               grim_uv_u0[2 * i + 1]};
  return rtx_effect_vertices(quad, 4);
}

extern "C" void rtx_plasma(int slot, float alpha) {
  if (!drawing())
    return;
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
                      ax,
                      ay,
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
  if (!drawing())
    return;
  float ax = ex - sx, ay = ey - sy, len = sqrtf(ax * ax + ay * ay);
  if (len <= 1e-3f)
    return;
  ax /= len;
  ay /= len;
  // Consecutive arcs batch: each corner carries its local position and the
  // arc's length in strip scales (effect.frag), the length negative when the
  // strips end in the native cut (original bug 36).
  float reach = len / scale, shape = portable_preserve_bugs ? -reach : reach;
  const float local[4][2] = {{-16, -16}, {-16, 16}, {reach + 16, 16}, {reach + 16, -16}};
  unsigned color = rgba(.5f, .6f, 1, alpha);
  EffectVertex quad[4];
  for (int i = 0; i < 4; ++i) {
    float x = local[i][0] * scale, y = local[i][1] * scale;
    quad[i] = {sx + ax * x - ay * y, sy + ay * x + ax * y, shape, 1, color, local[i][0], local[i][1]};
  }
  enqueue(ARC, quad);
}

// The Pulse Gun's shot (effect.frag's pulseProfile and glow), drawn where and as
// the native sprite is: centered, `size` wide, turned by the sprite's angle.
extern "C" void rtx_pulse(float cx, float cy, float size, float angle, float r,
                          float g, float b, float a) {
  if (drawing())
    sprite(PULSE, cx, cy, size, size, angle, rgba(r, g, b, a));
}
