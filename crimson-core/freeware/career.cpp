// Career spawns (0x40f650), kill rewards (0x405e10), pickups (0x406900, 0x4103b0)
// and level thresholds / milestone creatures (0x408600) in crimson.exe 1.4.0.
#include "game.h"
#include <algorithm>
#include <cmath>
#include <cstdio>

extern "C" {
int freeware_arena_width = freeware::arena, freeware_arena_height = freeware::arena;
int freeware_bonus_count = FREEWARE_EDITION == 10002 ? 4 : 6, freeware_pickup_id, freeware_pickup_weapon;
int freeware_bonus_fire = 1, freeware_bonus_freeze = 2, freeware_bonus_weapon = 3;
int freeware_bonus_nuke = 4, freeware_bonus_shield = 5, freeware_bonus_time = 6;
vec2f_t freeware_pickup_position;
float freeware_pickup_time;
unsigned char freeware_spawn_enabled = 1;
int freeware_pending_perks;
void player_check_level();
}
namespace freeware {
int Game::next_level_xp() const { return int(1000 * std::pow(run.level + 1., FREEWARE_EDITION == 10002 ? double(1.7f) : 1.75)); }
void Game::check_level() {
  FrameGameScope scope(*this);
  player_state_table[0].freeware.experience = run.experience;
  player_state_table[0].freeware.level = run.level;
  freeware_pending_perks = run.pending;
  player_check_level();
  run.level = player_state_table[0].freeware.level;
  run.pending = freeware_pending_perks;
}
} // namespace freeware
