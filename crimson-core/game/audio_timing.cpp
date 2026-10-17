// Sound admission follows simulation time during a run. The outer frame still
// streams music and updates fades, but must not age the same cooldowns again.
#include "crimsonland_audio.h"
#include "crimsonland_gameplay.h"

extern "C" bool game_live_run();
extern "C" bool game_coop_quiet();

namespace {
bool ticked;

void advance(float dt) {
  if (config_blob.sound_disabled)
    return;
  for (int i = 0; i < 128; ++i)
    if (sfx_cooldown_table[i] > 0.0f)
      sfx_cooldown_table[i] -= dt;
}
} // namespace

// A co-op tick a rollback runs again aged them the first time (host/coop.inc).
extern "C" void game_audio_tick(float dt) {
  if (!game_coop_quiet())
    advance(dt);
  ticked = true;
}

// Called by recovered audio_update, after a frame's gameplay. Menus keep the
// original frame clock; a frame containing ticks has already aged cooldowns.
extern "C" void game_audio_cooldowns(float dt) {
  // Replay frames draw even when no tick is due. They must not add a second
  // clock to the simulation's cooldowns (or age them while the replay pauses).
  if (!ticked && !(game_live_run() && game_state_id == GAME_STATE_GAMEPLAY))
    advance(dt);
  ticked = false;
}
