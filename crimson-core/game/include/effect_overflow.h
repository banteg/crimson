#pragma once
#include "crimsonland_gameplay.h"

// Original bug 39: extra slots reserved for non-blood effects when the original
// 511-slot pool is full, with their own decal queue so expiring overflow
// particles never displace original fx_queue entries.
constexpr int GAME_EFFECT_POOL_CAPACITY = 512;
constexpr int GAME_EFFECT_OVERFLOW_CAPACITY = 2048;
constexpr int GAME_EFFECT_ID_BLOOD = 7;
constexpr int GAME_FX_QUEUE_MAX_COUNT = 0x7f;
struct GameEffectOverflow {
  effect_entry_t entries[GAME_EFFECT_OVERFLOW_CAPACITY];
  fx_queue_entry_t decals[GAME_EFFECT_OVERFLOW_CAPACITY];
  effect_entry_t *free;
  int active, extent, decal_count;
};
extern GameEffectOverflow game_effect_overflow;

extern "C" {
void game_effects_reset();
effect_entry_t *game_effects_allocate(int effect_id);
bool game_effects_free(effect_entry_t *entry);
void game_effects_decal(effect_entry_t *entry);
void game_effects_render_decals();
int game_effects_active();
}

inline int game_effects_extent() { return GAME_EFFECT_POOL_CAPACITY + game_effect_overflow.extent; }
inline effect_entry_t *game_effects_entry(int index) {
  return index < GAME_EFFECT_POOL_CAPACITY
             ? &effect_pool[index]
             : &game_effect_overflow.entries[index - GAME_EFFECT_POOL_CAPACITY];
}
