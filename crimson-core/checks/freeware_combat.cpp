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
