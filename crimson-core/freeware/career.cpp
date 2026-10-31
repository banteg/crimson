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
void Game::spawn_career() {
  player_state_table[current_player_index].freeware.experience = run.experience;
  // Edge and coordinate consume separate CRT rand calls. Crowded spawns retry up to 100 times.
  for (int i = 0; i < 100; ++i) {
    const int edge = crt_rand() % 4;
    const float along = float(crt_rand() % arena);
    const vec2f_t edges[] = {{along, -40}, {along, arena + 40}, {-40, along}, {arena + 40, along}};
    if (creature_spawn_random(&edges[edge]))
      break;
  }
}
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
void Game::update_bomb(float dt) {
  if (run.bomb_age < 0)
    return;
  run.bomb_age += (1 + run.bomb_age) * dt * 1.8f;
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
    if (marks.size() < 128)
      marks.push_back({c.position, 16, 0, false});
    if (c.health <= 0)
      kill(i, 0);
  }
}
void Game::update_career(float dt) {
  run.pickup.time -= dt;
  for (int i = 0; i < players(); ++i) {
    auto &p = actor(i);
    if (p.health <= 0 || run.pickup.time <= 0 ||
        std::hypot(p.player.x - run.pickup.pos.x, p.player.y - run.pickup.pos.y) >= 32)
      continue;
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
  if (run.perks[7] || run.perks[18]) {
    for (int i = 0; i < players(); ++i) {
      if (actor(i).health <= 0)
        continue;
      int target = creature_find_in_radius(&player_state_table[i].freeware.aim, 10);
      if (target < 0)
        continue;
      auto &c = creature_pool[target];
      if (run.perks[7]) {
        c.anim_phase -= dt;
        if (c.anim_phase < 0) {
          c.anim_phase = .5f;
          vec2f_t zero{};
          for (float energy : {.8f, .6f, .4f, .3f, .2f})
            fx_spawn_particle(&c.position, (crt_rand() % 628) * .01f, &zero, energy);
          if (marks.size() < 128)
            marks.push_back({c.position, 16, 0, false});
        }
      }
      if (run.perks[18] && run.freeze <= 0) {
        c.pos_x -= c.vel_x;
        c.pos_y -= c.vel_y;
      }
    }
  }
  if (run.perks[17]) {
    run.jinx -= dt;
    if (run.jinx < 0) {
      if (crt_rand() % 10 == 3) {
        run.health -= 5;
        marks.push_back({run.player, 16, 0, false});
        marks.push_back({run.player, 16, 0, false});
      }
      run.jinx += (crt_rand() % 20) * .1f + 2;
      int id = crt_rand() % 511;
      for (int attempt = 0; attempt < 10 && !creature_pool[id].active; ++attempt)
        id = crt_rand() % 511;
      auto &c = creature_pool[id];
      if (c.active) {
        c.health = -1;
        c.death_timer -= dt * 20;
        run.experience = int(run.experience + c.freeware.reward);
        play_sound(Sound::Die);
      }
    }
  }
  if (run.perks[13]) {
    run.berserk -= dt;
    if (run.berserk < 0)
      run.berserk = crt_rand() % 15 == 2 ? 12 : 2;
  }
}
} // namespace freeware
