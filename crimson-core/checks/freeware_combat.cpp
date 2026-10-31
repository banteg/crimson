// Minimal host for stepping the same combat bodies linked into both clients.
#include "../freeware/game.h"
namespace freeware {
void play_sound(Sound) {}
void play_original_sample(int) {}
} // namespace freeware
static freeware::Game game;
extern "C" void combat_reset(unsigned seed) {
  game = freeware::Game{};
  game.survival = true;
  game.start();
  freeware::seed_random(seed);
}
extern "C" void combat_projectiles(float dt, float clock, float freeze) {
  game.run.freeze = freeze;
  freeware_simulation_clock = clock;
  game.update_projectiles(dt);
}
extern "C" int combat_experience() { return game.run.experience; }
extern "C" void combat_actors(int mode, int perk, int partner, float shield) {
  game.survival = mode == 2;
  game.two_players = true;
  game.run.player = {500, 500};
  game.run.partner.player = {600, 500};
  game.run.health = partner ? 0 : 100;
  game.run.partner.health = 100;
  game.run.shield = shield;
  game.run.perks[perk] = 1;
  player_state_table[0].freeware.perks[perk] = 1;
  extern game_mode_id_t config_game_mode;
  config_game_mode = static_cast<game_mode_id_t>(mode);
}
extern "C" void combat_creatures(float dt, float clock, float freeze) {
  freeware_simulation_clock = clock;
  game.run.freeze = freeze;
  game.update_creatures(dt);
}
extern "C" int combat_drop() { return game.run.pickup.time > 0 ? int(game.run.pickup.kind) : -1; }
extern "C" int combat_drop_weapon() { return game.run.pickup.weapon; }
extern "C" int combat_first_xp() { return game.run.first_kill_xp; }
extern "C" void combat_reward(float dt, float freeze, bool corpse) {
  frame_dt = dt;
  game.run.freeze = freeze;
  game.kill(0, 0, corpse);
}
