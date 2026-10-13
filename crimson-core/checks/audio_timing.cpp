#include "crimsonland_audio.h"
#include "crimsonland_gameplay.h"
#include <cassert>
#include <cstdio>
Config config_blob;
float sfx_cooldown_table[128];
int game_state_id;
static bool live;
extern "C" bool game_live_run() { return live; }
extern "C" void game_audio_tick(float);
extern "C" void game_audio_cooldowns(float);
int main() {
  live = true; game_state_id = GAME_STATE_GAMEPLAY;
  // A zero-tick replay frame cannot age a gameplay sound; neither can the
  // outer frame after a tick. Four 60 Hz ticks admit the next powered shot.
  sfx_cooldown_table[0] = 0.05f;
  game_audio_cooldowns(1.0f / 120);
  assert(sfx_cooldown_table[0] == 0.05f);
  for (int i = 0; i < 4; ++i) {
    game_audio_tick(1.0f / 60);
    float expected = sfx_cooldown_table[0];
    game_audio_cooldowns(1.0f / 120);
    assert(sfx_cooldown_table[0] == expected);
  }
  assert(sfx_cooldown_table[0] <= 0);
  // Several catch-up ticks expire it before another shot in the same frame.
  sfx_cooldown_table[0] = 0.05f;
  for (int i = 0; i < 4; ++i) game_audio_tick(1.0f / 60);
  assert(sfx_cooldown_table[0] <= 0);
  float remainder = sfx_cooldown_table[0];
  // A tick opening a menu must not count both clocks on that frame.
  game_state_id = 0;
  game_audio_cooldowns(0.1f);
  assert(sfx_cooldown_table[0] == remainder);
  sfx_cooldown_table[0] = 0.05f;
  game_audio_cooldowns(0.02f);
  assert(sfx_cooldown_table[0] == 0.05f - 0.02f);
  // Preserve the original disabled-audio gate and negative zero crossing.
  config_blob.sound_disabled = true;
  game_audio_tick(1);
  game_audio_cooldowns(1);
  assert(sfx_cooldown_table[0] == 0.05f - 0.02f);
  config_blob.sound_disabled = false;
  game_audio_cooldowns(1);
  remainder = sfx_cooldown_table[0];
  assert(remainder < 0);
  game_audio_cooldowns(1);
  assert(sfx_cooldown_table[0] == remainder);
  puts("audio cooldown clocks: passed");
}
