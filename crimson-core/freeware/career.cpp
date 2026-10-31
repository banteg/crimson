// Career spawns (0x40f650), kill rewards (0x405e10), pickups (0x406900, 0x4103b0)
// and level thresholds / milestone creatures (0x408600) in crimson.exe 1.4.0.
#include "game.h"
#include <algorithm>
#include <cmath>
#include <cstdio>

extern "C" {
int freeware_arena_width = freeware::arena, freeware_arena_height = freeware::arena;
int freeware_bonus_count = 6, freeware_pickup_id, freeware_pickup_weapon;
int freeware_bonus_fire = 1, freeware_bonus_freeze = 2, freeware_bonus_weapon = 3;
int freeware_bonus_nuke = 4, freeware_bonus_shield = 5, freeware_bonus_time = 6;
vec2f_t freeware_pickup_position;
float freeware_pickup_time;
unsigned char freeware_spawn_enabled = 1;
int freeware_pending_perks;
void player_check_level();
}
namespace freeware {
int Game::next_level_xp() const { return int(1000 * std::pow(run.level + 1., 1.75)); }
void Game::check_level() {
  player_state_table[0].freeware.experience = run.experience;
  player_state_table[0].freeware.level = run.level;
  freeware_pending_perks = run.pending;
  player_check_level();
  run.level = player_state_table[0].freeware.level;
  run.pending = freeware_pending_perks;
}
// The dispatcher advances the wave. The effects pass (0x4121e6) damages each living creature inside it.
void Game::apply_bomb_damage(float dt) {
  if (run.bomb_age < 0)
    return;
  if (run.bomb_age > 1) {
    run.bomb_age = -1;
    return;
  }
  for (int i = 0; i < 512; ++i) {
    auto &c = creature_pool[i];
    if (!c.active || c.health <= 0 ||
        std::hypot(c.pos_x - run.bomb_pos.x, c.pos_y - run.bomb_pos.y) >= run.bomb_age * 256)
      continue;
    c.health -= dt * 2000;
    queue_blood(c.position);
    if (c.health <= 0)
      kill(i, 0);
  }
}
void Game::collect_pickup(int i) {
  auto &p = actor(i);
  if (p.health <= 0 || run.pickup.time <= 0 ||
      std::hypot(p.player.x - run.pickup.pos.x, p.player.y - run.pickup.pos.y) >= 32)
    return;
  auto &w = player_state_table[i].freeware;
  switch (run.pickup.kind) {
  case Bonus::Fire:
    bonus_fire_bullets_timer = 8;
    break;
  case Bonus::Freeze:
    run.freeze = 5;
    break;
  case Bonus::Weapon:
    weapon_assign_player(i, run.pickup.weapon);
    break;
  case Bonus::Nuke:
    run.bomb_age = 0;
    run.bomb_pos = run.pickup.pos;
    camera_shake = {10, 10};
    play_sound(Sound::Explosion);
    break;
  case Bonus::Shield:
    p.shield = 6;
    break;
  case Bonus::Time:
    w.ammo = w.clip_size;
    p.cooldown = -.1f;
    run.slow = 4;
    break;
  }
  play_sound(Sound::Bonus);
  run.pickup.time = 0;
}
} // namespace freeware
