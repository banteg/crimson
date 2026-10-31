// Career spawns (0x40f650), kill rewards (0x405e10), pickups (0x406900, 0x4103b0)
// and level thresholds / milestone creatures (0x408600) in crimson.exe 1.4.0.
#include "game.h"
#include <algorithm>
#include <cmath>
#include <cstdio>

extern "C" {
int freeware_arena_width = freeware::arena, freeware_arena_height = freeware::arena;
int freeware_bonus_count = 6, freeware_bonus_ids[6] = {0, 1, 2, 3, 4, 5}, freeware_pickup_id,
    freeware_pickup_weapon;
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
void Game::kill(int slot, int owner, bool corpse) {
  auto &c = creature_pool[slot];
  if (!c.active)
    return;
  if (corpse)
    c.death_timer -= frame_dt;
  else
    c.active = 0;
  --creature_spawned_count;
  int reward = int(c.freeware.reward * (run.perks[1] ? 1.5 : 1.0));
  if (!run.experience && !run.moved) {
    run.first_kill_xp = int(c.freeware.reward);
    run.first_kill_pos = c.position;
  }
  run.experience += reward;
  if (++run.kills == 1)
    std::puts("1.4.0 first kill");

  if (!survival && run.pickup.time <= 0) {
    auto &weapon = player_state_table[owner].freeware.weapon;
    bool drop = crt_rand() % 8 == 1 || (weapon == 1 && crt_rand() % 3 == 1);
    auto pos = c.position;
    if (drop && std::hypot(pos.x - actor(owner).player.x, pos.y - actor(owner).player.y) > 64) {
      freeware_pickup_time = 0;
      bonus_spawn_at(&pos);
      if (freeware_pickup_time > 0)
        run.pickup = {freeware_pickup_position, static_cast<Bonus>(freeware_pickup_id), freeware_pickup_time,
                      freeware_pickup_weapon};
    }
  }
  if (run.freeze != 0) {
    for (int i = 0; i < 30; ++i) {
      float size = float(crt_rand() % 10 + 5);
      float heading = (crt_rand() % 628) * .01f;
      float radius = i * .04f * (crt_rand() % 55);
      vec2f_t mark{c.pos_x + std::cos(heading) * radius, c.pos_y + std::sin(heading) * radius};
      float rotation = (crt_rand() % 612) * .01f;
      if (marks.size() < 128)
        marks.push_back({mark, size, rotation, true});
    }
    vec2f_t zero{};
    auto &mist = sprite_effect_pool[fx_spawn_sprite(&c.position, &zero, 12)];
    mist.color_r *= .56f;
    mist.color_g *= .7f;
    mist.color_b *= .9f;
    c.active = 0;
  }
}
int Game::next_level_xp() const { return int(1000 * std::pow(run.level + 1., 1.75)); }
void Game::update_career(float dt) {
  player_state_table[0].freeware.experience = run.experience;
  player_state_table[0].freeware.level = run.level;
  freeware_pending_perks = run.pending;
  player_check_level();
  run.level = player_state_table[0].freeware.level;
  run.pending = freeware_pending_perks;
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
      w.reload = 0;
      run.slow = 4;
      break;
    }
    play_sound(Sound::Bonus);
    run.pickup.time = 0;
  }
  if (run.bomb_age >= 0) {
    run.bomb_age += dt;
    for (int i = 0; i < 512; ++i) {
      auto &c = creature_pool[i];
      if (c.active && c.death_timer == 16 && c.health > 0 &&
          std::hypot(c.pos_x - run.bomb_pos.x, c.pos_y - run.bomb_pos.y) < run.bomb_age * 360) {
        c.health = 0;
        kill(i, 0);
      }
    }
    if (run.bomb_age > 1)
      run.bomb_age = -1;
  }
  if (run.perks[6]) {
    run.exp_clock -= dt;
    if (run.exp_clock < 0) {
      run.experience += 10 * run.perks[6];
      run.exp_clock = .25f;
    }
  }
  if (!two_players && !survival && run.health > 0) {
    float dist = std::hypot(run.player.x - run.first_kill_pos.x, run.player.y - run.first_kill_pos.y);
    if (run.health < 100 && dist >= 48)
      run.first_kill_xp = -10;
    if (run.health < 5 && dist < 48 && run.first_kill_xp == run.experience &&
        player_state_table[0].freeware.weapon != 18) {
      freeware_secret_weapon_unlocked = 1;
      weapon_assign_player(0, 18);
    }
    if (!run.experience && run.seconds >= 120 && !highscore_record_shots_fired && run.health == 100) {
      run.experience = 1;
      freeware_secret_weapon_unlocked = 1;
      weapon_assign_player(0, 19);
    }
  }
  if (run.perks[13]) {
    run.berserk -= dt;
    if (run.berserk < 0)
      run.berserk = crt_rand() % 15 == 2 ? 12 : 2;
  }
  if (run.perks[17]) {
    run.jinx -= dt;
    if (run.jinx <= 0) {
      if (crt_rand() % 10 == 3)
        run.health -= 1;
      run.jinx = 2 + (crt_rand() % 20) * .1f;
      for (int attempt = 0; attempt < 10; ++attempt) {
        int id = crt_rand() % 511;
        if (!creature_pool[id].active || creature_pool[id].health <= 0)
          continue;
        creature_pool[id].health -= dt * 100;
        if (creature_pool[id].health <= 0)
          kill(id, 0);
        break;
      }
    }
  }
}
} // namespace freeware
