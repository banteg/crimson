// Compile the actual adapted allocation/update code: pool ownership, on-demand
// extent growth, expiry, decal queueing and run resets must agree.
#include "effect_overflow.h"
#include <cassert>
#include <cstdio>

effect_pool_t effect_pool;
effect_entry_t effect_discard_entry, *effect_free_list_head;
effect_template_t effect_template;
effect_vec2_t effect_template_position;
effect_id_entry_t effect_id_table[32];
uv2f_t effect_uv2[4], effect_uv4[16], effect_uv8[64], effect_uv16[256];
float frame_dt;
int effect_defaults_reserved_zero, effect_pool_reserved_zero;
fx_queue_entry_t fx_queue[128];
int fx_queue_count, fx_queue_rotated;
extern "C" {
unsigned char portable_preserve_bugs, terrain_texture_failed;
int config_detail_preset = 5, effect_spawn_detail_skip_counter;
float effect_uv_step_2 = 0.5f, effect_uv_step_4 = 0.25f, effect_uv_step_8 = 0.125f, effect_uv_step_16 = 0.0625f;
}
static int decals, render_calls, rendered_decals[512], rendered_count, rendered_rotated[8], rotated_total;
unsigned char fx_queue_add(int, vec2f_t *, float, float, float, effect_color_t *) {
  ++decals;
  return 1;
}
extern "C" void fx_queue_render_recovered() {
  rendered_rotated[render_calls++] = fx_queue_rotated;
  if (terrain_texture_failed)
    return;
  for (int i = 0; i < fx_queue_count; ++i)
    rendered_decals[rendered_count++] = fx_queue[i].effect_id;
  rotated_total += fx_queue_rotated;
  fx_queue_count = fx_queue_rotated = 0;
}
static effect_entry_t *spawn(int id = 1) {
  vec2f_t pos = {12, 34};
  return effect_spawn(id, &pos);
}
static void fill_original() {
  for (int i = 0; i < GAME_EFFECT_POOL_CAPACITY - 1; ++i)
    assert(spawn(GAME_EFFECT_ID_BLOOD) == &effect_pool[i]);
  assert(spawn(GAME_EFFECT_ID_BLOOD) == &effect_discard_entry);
}
static void fill_overflow(int count) {
  for (int i = 0; i < count; ++i)
    assert(spawn() != &effect_discard_entry);
  assert(spawn() == &effect_discard_entry);
  assert(game_effect_overflow.active == count);
}

int main() {
  effect_defaults_reset();
  assert(game_effects_extent() == GAME_EFFECT_POOL_CAPACITY);
  fill_original();
  auto *original_head = effect_free_list_head;
  // --preserve-bugs keeps the original 511-slot cap.
  portable_preserve_bugs = 1;
  assert(spawn() == &effect_discard_entry);
  assert(game_effect_overflow.active == 0);
  portable_preserve_bugs = 0;
  // Low detail still skips exactly the original alternating attempts.
  config_detail_preset = 2;
  auto *first = spawn();
  assert(first != &effect_discard_entry);
  assert(spawn() == &effect_discard_entry);
  assert(game_effect_overflow.active == 1);
  assert(game_effects_extent() == GAME_EFFECT_POOL_CAPACITY + 1);
  effect_free(first);
  assert(game_effect_overflow.active == 0);
  assert(game_effects_extent() == GAME_EFFECT_POOL_CAPACITY);
  config_detail_preset = 5;
  // Freed overflow slots below the high-water mark are reused before growing extent.
  auto *a = spawn();
  auto *b = spawn();
  assert(game_effect_overflow.active == 2);
  assert(game_effects_extent() == GAME_EFFECT_POOL_CAPACITY + 2);
  effect_free(a);
  assert(game_effect_overflow.active == 1);
  assert(game_effects_extent() == GAME_EFFECT_POOL_CAPACITY + 2);
  assert(spawn() == a);
  assert(game_effect_overflow.active == 2);
  assert(game_effects_extent() == GAME_EFFECT_POOL_CAPACITY + 2);
  effect_free(a);
  effect_free(b);
  assert(game_effects_extent() == GAME_EFFECT_POOL_CAPACITY);

  fill_overflow(GAME_EFFECT_OVERFLOW_CAPACITY);
  assert(game_effects_extent() == GAME_EFFECT_POOL_CAPACITY + GAME_EFFECT_OVERFLOW_CAPACITY);
  assert(effect_free_list_head == original_head);
  assert(spawn(GAME_EFFECT_ID_BLOOD) == &effect_discard_entry);
  // Reusing an ordinary slot takes precedence, even with full overflow.
  effect_free(&effect_pool[0]);
  assert(spawn(GAME_EFFECT_ID_BLOOD) == &effect_pool[0]);
  assert(game_effect_overflow.active == GAME_EFFECT_OVERFLOW_CAPACITY);

  frame_dt = 0.1f;
  effects_update();
  assert(game_effect_overflow.entries[GAME_EFFECT_OVERFLOW_CAPACITY - 1].age == 0.1f);
  for (int i = 0; i < 300; ++i) {
    auto *decal = &game_effect_overflow.entries[i];
    decal->flags |= 0x80;
    decal->effect_id = (unsigned char)(50 + i);
  }
  frame_dt = 1;
  effects_update();
  // Overflow decals use their own queue instead of contending for fx_queue.
  assert(decals == 0);
  assert(game_effect_overflow.decal_count == 300);
  assert(game_effect_overflow.active == 0);
  assert(game_effects_extent() == GAME_EFFECT_POOL_CAPACITY);
  for (int i = 0; i < 50; ++i)
    fx_queue[i].effect_id = i;
  fx_queue_count = 50;
  fx_queue_rotated = 3;
  game_effects_render_decals();
  // 350 decals split into 127 + 127 + 96; corpses bake only on the final chunk.
  assert(render_calls == 3);
  assert(rendered_count == 350);
  assert(rendered_rotated[0] == 0 && rendered_rotated[1] == 0 && rendered_rotated[2] == 3);
  assert(rotated_total == 3);
  for (int i = 0; i < 350; ++i)
    assert(rendered_decals[i] == (unsigned char)i);

  // Safemode fallback draws corpses once without re-running for overflow decals.
  render_calls = 0;
  terrain_texture_failed = 1;
  fx_queue_rotated = 2;
  game_effect_overflow.decal_count = 200;
  game_effects_render_decals();
  assert(render_calls == 1);
  assert(game_effect_overflow.decal_count == 0);
  terrain_texture_failed = 0;

  // A new match resets particles, pending overflow decals and the overflow extent.
  game_effect_overflow.decal_count = 5;
  effect_defaults_reset();
  assert(game_effect_overflow.decal_count == 0);
  fill_original();
  for (int i = 0; i < 8; ++i)
    assert(spawn() != &effect_discard_entry);
  assert(game_effect_overflow.active == 8);
  assert(game_effects_extent() == GAME_EFFECT_POOL_CAPACITY + 8);
  effect_defaults_reset();
  assert(game_effect_overflow.active == 0);
  assert(game_effects_extent() == GAME_EFFECT_POOL_CAPACITY);
  puts("effect overflow: allocation, free-list reuse, extent, expiry, decal queueing and resets passed");
}
