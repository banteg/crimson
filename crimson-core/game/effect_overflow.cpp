#include "effect_overflow.h"
#include <stdint.h>
#include <string.h>

GameEffectOverflow game_effect_overflow;

extern "C" {
extern unsigned char portable_preserve_bugs;
extern unsigned char terrain_texture_failed;
void fx_queue_render_recovered();

__attribute__((export_name("game_effects_active"))) int game_effects_active() { return game_effect_overflow.active; }

void game_effects_reset() {
  game_effect_overflow.free = nullptr;
  game_effect_overflow.active = game_effect_overflow.extent = game_effect_overflow.decal_count = 0;
}

// Called only after the original detail-level gate and after the spawner's
// random parameters have been drawn. Neither success nor failure draws RNG.
effect_entry_t *game_effects_allocate(int effect_id) {
  effect_entry_t *entry = effect_free_list_head;
  if (entry->next_free) {
    effect_free_list_head = entry->next_free;
    return entry;
  }
  if (portable_preserve_bugs || effect_id == GAME_EFFECT_ID_BLOOD)
    return &effect_discard_entry;
  if (game_effect_overflow.free) {
    entry = game_effect_overflow.free;
    game_effect_overflow.free = entry->next_free;
  } else if (game_effect_overflow.extent < GAME_EFFECT_OVERFLOW_CAPACITY) {
    entry = &game_effect_overflow.entries[game_effect_overflow.extent++];
    effect_init_entry(entry);
    entry->next_free = nullptr;
  } else {
    return &effect_discard_entry;
  }
  ++game_effect_overflow.active;
  return entry;
}

bool game_effects_free(effect_entry_t *entry) {
  uintptr_t at = (uintptr_t)entry, begin = (uintptr_t)game_effect_overflow.entries;
  if (at < begin || at >= begin + sizeof game_effect_overflow.entries)
    return false;
  entry->flags = 0;
  if (--game_effect_overflow.active == 0) {
    game_effect_overflow.free = nullptr;
    game_effect_overflow.extent = 0;
  } else {
    entry->next_free = game_effect_overflow.free;
    game_effect_overflow.free = entry;
  }
  return true;
}

void game_effects_decal(effect_entry_t *entry) {
  if (game_effect_overflow.decal_count >= GAME_EFFECT_OVERFLOW_CAPACITY)
    return;
  fx_queue_entry_t &decal = game_effect_overflow.decals[game_effect_overflow.decal_count++];
  decal.position = entry->position;
  decal.color = entry->color;
  decal.width = entry->half_width + entry->half_width;
  decal.height = entry->half_height + entry->half_height;
  decal.rotation = entry->rotation;
  decal.effect_id = entry->effect_id;
}

void game_effects_render_decals() {
  int overflow = game_effect_overflow.decal_count;
  game_effect_overflow.decal_count = 0;
  if (terrain_texture_failed) {
    fx_queue_render_recovered();
    return;
  }
  int rotated = fx_queue_rotated;
  for (int at = 0; at < overflow;) {
    int n = GAME_FX_QUEUE_MAX_COUNT - fx_queue_count;
    if (n > overflow - at)
      n = overflow - at;
    memcpy(fx_queue + fx_queue_count, game_effect_overflow.decals + at, (size_t)n * sizeof(fx_queue_entry_t));
    fx_queue_count += n;
    at += n;
    if (at < overflow) {
      fx_queue_rotated = 0;
      fx_queue_render_recovered();
    }
  }
  fx_queue_rotated = rotated;
  fx_queue_render_recovered();
}
}
