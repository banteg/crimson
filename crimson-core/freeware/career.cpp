// Career spawns (0x40f650), kill rewards (0x405e10), pickups (0x406900, 0x4103b0)
// and level thresholds / milestone creatures (0x408600) in crimson.exe 1.4.0.
#include "game.h"
#include <algorithm>
#include <cmath>
#include <cstdio>

namespace freeware {
static bool spawn_at(vec2f_t pos, int xp) {
  const int id = creature_alloc_slot();
  auto &c = creature_pool[id];
  c.position = pos;
  if (plaguebearer_spread_infection(id))
    return false;
  auto &s = c.freeware;
  c.plague_infected = 0;
  c.anim_phase = 0;
  s.type = crt_rand() % 2 == 0 ? 2 : 1;
  c.active = 1;
  s.force_target = 0;
  c.death_timer = 16;
  c.velocity = {};
  s.heading = (crt_rand() % 314) * .01f;
  s.move_speed = std::min(3.f, xp * (1.f / 21000) + .8f);
  c.health = xp * .00125f + 52;
  s.reward = xp * .00002f + (crt_rand() % 10 + 87);
  s.attack_cooldown = 0;
  s.color.r = std::clamp(1.f - 1.f / (xp + 1.f), 0.f, 1.f);
  s.color.g = (crt_rand() % 10) * .01f + .9f;
  s.color.b = (crt_rand() % 10) * .01f + .7f;
  s.color.a = 1;
  if (crt_rand() % 180 < 2) {
    c.health = 65;
    s.color = {.9f, .4f, .4f, 1};
    s.reward = 320;
  } else if (crt_rand() % 240 < 2) {
    c.health = 85;
    s.color = {.4f, .9f, .4f, 1};
    s.reward = 420;
  } else if (crt_rand() % 360 < 2) {
    c.health = 125;
    s.color = {.4f, .4f, .9f, 1};
    s.reward = 520;
  }
  s.size = float(crt_rand() % 28 + 42);
  if (crt_rand() % 1320 < 4) {
    s.size = 84;
    c.health += 230;
    s.color = {.84f, .24f, .89f, 1};
    s.reward = 600;
  }
  if (crt_rand() % 1620 < 4) {
    s.size = 92;
    c.health += 2230;
    s.color = {.94f, .84f, .29f, 1};
    s.reward = 900;
  }
  s.contact_damage = s.size * (1.f / 10.5f);
  c.ai_mode = 1;
  ++creature_spawned_count;
  return true;
}

void Game::spawn_career() {
  // Edge and coordinate consume separate CRT rand calls. Crowded spawns retry up to 100 times.
  for (int i = 0; i < 100; ++i) {
    const int edge = crt_rand() % 4;
    const float along = float(crt_rand() % arena);
    const vec2f_t edges[] = {{along, -40}, {along, arena + 40}, {-40, along}, {arena + 40, along}};
    if (spawn_at(edges[edge], run.experience))
      break;
  }
}
void Game::kill(int slot, int owner) {
  auto &c = creature_pool[slot];
  if (!c.active || c.death_timer < 16)
    return;
  c.health = std::min(0.f, c.health);
  c.death_timer = 15.999f;
  --creature_spawned_count;
  int reward = int(c.freeware.reward * (run.perks[1] ? 1.5 : 1.0));
  if (!run.experience && !run.moved) {
    run.first_kill_xp = reward;
    run.first_kill_pos = c.position;
  }
  run.experience += reward;
  if (++run.kills == 1)
    std::puts("1.4.0 first kill");
  play_sound(Sound::Die);
  if (survival || run.pickup.time > 0)
    return;
  auto &weapon = player_state_table[owner].freeware.weapon;
  if (crt_rand() % 8 != 1 && (weapon != 1 || crt_rand() % 3 != 1))
    return;
  auto pos = c.position;
  if (std::hypot(pos.x - actor(owner).player.x, pos.y - actor(owner).player.y) <= 64 || pos.x < 32 || pos.y < 32 ||
      pos.x > arena - 32 || pos.y > arena - 32)
    return;
  auto kind = static_cast<Bonus>(crt_rand() % 6);
  if (weapon == 1)
    kind = Bonus::Weapon;
  int item = 0;
  if (kind == Bonus::Weapon)
    do {
      item = crt_rand() % 14 + 2;
    } while (item == weapon);
  run.pickup = {pos, kind, 10, item};
}
int Game::next_level_xp() const { return int(1000 * std::pow(run.level + 1., 1.75)); }
static void spawn_boss(int level) {
  struct Boss {
    int level, type;
    float size, health, damage, speed;
    double xp;
    effect_color_t tint;
  };
  static const Boss bosses[] = {{3, 1, 92, 1200, 10, 1.2f, 2000, {28 / 255.f, 131 / 255.f, 174 / 255.f, 1}},
                                {5, 2, 98, 1400, 10, 1.2f, 3000, {192 / 255.f, 0, 192 / 255.f, 1}},
                                {8, 1, 128, 3000, 10, 1.2f, 5000, {192 / 255.f, 0, 0, 1}},
                                {13, 1, 128, 10000, 30, 2.6f, 4000, {.7f, .7f, .7f, .4f}},
                                {17, 1, 100, 10000, 30, 2.8f, 5000, {1, 1, 1, 1}}};
  for (auto &b : bosses)
    if (level == b.level) {
      auto &c = creature_pool[creature_alloc_slot()];
      c.active = c.ai_mode = 1;
      c.position = {-20, -20};
      c.velocity = {};
      c.death_timer = 16;
      c.health = b.health;
      auto &s = c.freeware;
      if (level == 8 || level == 17)
        c.hit_flash_timer = -.5f;
      s.type = b.type;
      s.heading = crt_rand() % 314 * .01f;
      s.size = b.size;
      s.contact_damage = b.damage;
      s.move_speed = b.speed;
      s.color = b.tint;
      s.reward = b.xp;
      s.attack_cooldown = 0;
      s.force_target = 0;
      ++creature_spawned_count;
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
      if (c.active && c.health > 0 &&
          std::hypot(c.pos_x - run.bomb_pos.x, c.pos_y - run.bomb_pos.y) < run.bomb_age * 360)
        kill(i, 0);
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
  if (run.experience > next_level_xp()) {
    spawn_boss(++run.level);
    ++run.pending;
    play_sound(Sound::Level);
  }
}
} // namespace freeware
