// Monster Vision in RTX, after the Python port's src/crimson/render/rtx/heat_vision.py:
// living monsters read as heat. Each frame's footprints go to the host's
// world-space trail buffer (host_heat), and each species' bodies draw again as
// heat after its own (creature_render_type, game/rtx/rtx.patch). Visibility
// follows Monster Vision's native fade, never a creature's tint alpha, so Hidden
// Evil's near-invisible aliens show in full. Reading the run only.
#include "crimsonland_gameplay.h"
#include "grim2d_cpp.h"
#include "host_abi.h"
#include <math.h>

extern IGrim2D_cpp *grim_interface_ptr;
extern "C" {
extern int perk_id_monster_vision;
extern vec2f_t camera_offset;
extern creature_type_table_t creature_type_table;
bool rtx_drawing();
}

namespace {

// A footprint's radius, as a share of the creature's size; the bodies' overlay
// opacity; the share of its warmth a monster keeps while Freeze holds it.
const float FOOTPRINT = 0.45f, BODY_OPACITY = 0.88f, FROZEN_WARMTH = 0.3f;

float fade(const creature_t &c) {
  return c.death_timer >= 0 ? 1.0f : fminf(1, fmaxf(0, (c.death_timer + 10) * 0.1f));
}

// Its native fade, cooled while Freeze holds it, with Freeze's own fade out.
// Scene transitions fade the heat's opacity, never its warmth.
float warmth(const creature_t &c) {
  return fade(c) * (1 - (1 - FROZEN_WARMTH) * fminf(1, fmaxf(0, bonus_freeze_timer)));
}

bool heat_vision() { return rtx_drawing() && perk_count_get(perk_id_monster_vision); }

} // namespace

// Every warm monster's footprint, as world x, y, radius and warmth: the trail
// buffer covers the terrain, so offscreen monsters lay heat too.
extern "C" int rtx_collect_heat(float *out, int capacity) {
  if (!perk_count_get(perk_id_monster_vision))
    return 0;
  int count = 0;
  for (const creature_t &c : creature_pool) {
    float w = c.active ? warmth(c) : 0;
    if (w <= 1e-3f || count >= capacity)
      continue;
    float *f = out + count++ * 4;
    f[0] = c.pos_x, f[1] = c.pos_y, f[2] = c.size * FOOTPRINT, f[3] = w;
  }
  return count;
}

// The trails, added to the ground under every body at the world's transition
// `alpha`, where the native aura drew (creature_render_all).
extern "C" void rtx_heat_trails(float alpha) {
  if (!heat_vision())
    return;
  grim_interface_ptr->grim_flush_batch();
  host_heat_trails(alpha);
}

// The species' bodies again in heat_body.frag: red is warmth, alpha the
// overlay's opacity. The same frames and quads creature_render_type draws, with
// the creature atlas and blending it left bound.
extern "C" void rtx_heat(int type_id, float transition_alpha) {
  if (!heat_vision())
    return;
  grim_interface_ptr->grim_flush_batch();
  host_render_pass(HOST_PASS_HEAT);
  grim_interface_ptr->grim_begin_batch();
  for (const creature_t &c : creature_pool) {
    float opacity = c.active && c.type_id == type_id ? fade(c) * transition_alpha : 0;
    if (opacity <= 1e-3f)
      continue;
    int flags = c.flags, frame;
    if ((flags & CREATURE_FLAG_SPAWNER) && !(flags & CREATURE_FLAG_SPAWNER_MOBILE)) {
      frame = (int)(c.anim_phase + 0.5f) % 16;
      frame = (frame > 7 ? 15 - frame : frame) + creature_type_table[type_id].base_frame + 16;
    } else {
      if (c.death_timer < 16)
        frame = c.death_timer < 0 ? creature_type_table[type_id].base_frame + 15
                                  : (int)((float)(creature_type_table[type_id].base_frame + 15) - c.death_timer);
      else if ((frame = (int)(c.anim_phase + 0.5f)) > 15 && (creature_type_table[type_id].anim_flags & 1))
        frame = 31 - frame;
      if (flags & CREATURE_FLAG_RANGED_PLASMA_RIFLE)
        frame += 32;
    }
    grim_interface_ptr->grim_set_atlas_frame(8, frame);
    grim_interface_ptr->grim_set_color(warmth(c), 0, 0, fminf(1, opacity) * BODY_OPACITY);
    grim_interface_ptr->grim_set_rotation(c.heading - 1.57079637f);
    grim_interface_ptr->grim_draw_quad(camera_offset.x + c.pos_x - c.size * 0.5f,
                                       camera_offset.y + c.pos_y - c.size * 0.5f, c.size, c.size);
  }
  grim_interface_ptr->grim_end_batch();
  grim_interface_ptr->grim_flush_batch();
  host_render_pass(HOST_PASS_SPRITES);
}
