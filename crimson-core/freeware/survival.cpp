// Single-player Survival branches of crimson.exe 1.4.0. Addresses below are VAs in the pinned image.
#include "game.h"
#include <algorithm>
#include <cmath>
#include <cstdio>
#include <cstring>

extern "C" {
creature_t creature_pool[512];
projectile_pool_t projectile_pool;
float frame_dt, bonus_fire_bullets_timer, freeware_elapsed_seconds;
game_mode_id_t config_game_mode = static_cast<game_mode_id_t>(2);
int creature_spawned_count;
int creature_spawn(const vec2f_t *, const effect_color_t *, int);
int highscore_record_shots_fired;
int creature_alloc_slot();
void creature_reset_all();
int creature_find_in_radius(const vec2f_t *, float);
int projectile_spawn(const vec2f_t *, float, int);
float angle_approach(float *, float, float);
}

namespace freeware {
constexpr float pi = 3.14159265f;
static_assert(sizeof(creature_t) == 0x80 && sizeof(projectile_t) == 0x34);

float camera_x(const Game &g) { return std::clamp(width * .5f - g.run.player.x, float(width - arena), 0.f); }
float camera_y(const Game &g) { return std::clamp(height * .5f - g.run.player.y, float(height - arena), -1.f); }

static unsigned rng = 1;
extern "C" int crt_rand() {
  rng = rng * 214013u + 2531011u;
  return (rng >> 16) & 0x7fff;
}

void Game::start() {
  // Reset path 0x408e90 calls 0x408440 and clears all 64 shots and 512 creatures.
  run = Run{};
  creature_reset_all();
  std::memset(projectile_pool, 0, sizeof(projectile_pool));
  highscore_record_shots_fired = 0;
  creature_spawned_count = 0;
  freeware_elapsed_seconds = 0;
  bonus_fire_bullets_timer = 0;
  name.clear();
  paused = false;
  screen = Screen::Playing;
  ++generation;
  std::printf("1.4.0 survival start %d\n", generation);
}

static void update_creatures(Game &g, float dt) {
  // 0x40d8c0. Each living creature steers toward a point offset around its target.
  for (int i = 0; i < 512; ++i) {
    auto &c = creature_pool[i];
    if (!c.active)
      continue;
    auto &s = c.freeware;
    if (c.health <= 0 || c.death_timer < 16) {
      c.death_timer -= dt * 28;
      if (c.death_timer <= 0)
        c.active = 0;
      continue;
    }
    const auto p = g.run.player;
    float distance = std::hypot(p.x - c.pos_x, p.y - c.pos_y);
    const float offset = i * 3.7f * pi;
    s.target = {p.x + std::cos(offset) * distance * .85f, p.y + std::sin(offset) * distance * .85f};
    s.target_heading = std::atan2(s.target.y - c.pos_y, s.target.x - c.pos_x) + pi / 2;
    angle_approach(&s.heading, s.target_heading, 0);
    c.velocity = {std::cos(s.heading - pi / 2) * s.move_speed * dt * 30,
                  std::sin(s.heading - pi / 2) * s.move_speed * dt * 30};
    c.pos_x += c.velocity.x;
    c.pos_y += c.velocity.y;
    s.animation = std::fmod(s.animation + dt * s.move_speed * 26, 31.f);
    s.attack_cooldown = std::max(0.f, s.attack_cooldown - dt);
    distance = std::hypot(p.x - c.pos_x, p.y - c.pos_y);
    if (distance < 20) {
      c.pos_x -= c.velocity.x;
      c.pos_y -= c.velocity.y;
    }
    if (distance < 30 && s.attack_cooldown <= 0 && g.run.health > 0) {
      g.run.health -= s.contact_damage;
      s.attack_cooldown += 1;
      play_sound(Sound::Attack);
    }
  }
}

static void update_shots(Game &g, float dt) {
  // 0x4094e0. The AutoRifle advances in short steps and tests the actual creature pool after each step.
  for (auto &shot : projectile_pool) {
    if (!shot.active)
      continue;
    auto &p = shot.fields;
    if (p.life_timer < .4f) {
      p.life_timer -= dt;
      if (p.life_timer <= 0)
        shot.active = 0;
      continue;
    }
    const float dx = std::cos(shot.angle - pi / 2) * dt * 20;
    const float dy = std::sin(shot.angle - pi / 2) * dt * 20;
    for (int step = 0; step < 60; ++step) {
      shot.position.x += dx * p.speed_scale;
      shot.position.y += dy * p.speed_scale;
      if (shot.position.x < -10 || shot.position.y < -10 || shot.position.x > arena + 10 ||
          shot.position.y > arena + 10) {
        shot.active = 0;
        break;
      }
      int id = creature_find_in_radius(&shot.position, 0);
      if (id < 0)
        continue;
      auto &c = creature_pool[id];
      const float distance = std::max(50.f, std::hypot(p.origin.x - shot.position.x, p.origin.y - shot.position.y));
      if (c.death_timer == 16)
        ++g.run.hits;
      p.life_timer = .25f;
      if (c.health > 0) {
        c.health -= (3000 / distance + 10) * 1.2f * .95f;
        if (c.health <= 0) {
          ++g.run.kills;
          g.run.experience += static_cast<int>(c.freeware.reward);
          c.death_timer -= dt;
          play_sound(Sound::Die);
          if (g.run.kills == 1)
            std::puts("1.4.0 first kill");
        } else
          play_sound(Sound::Hit);
      }
      break;
    }
  }
}

void Game::tick(float dt, const Input &in) {
  frame_dt = dt;
  run.seconds += dt;
  freeware_elapsed_seconds = run.seconds;
  float dx = float(in.right) - float(in.left), dy = float(in.down) - float(in.up);
  if (dx || dy) {
    float length = std::hypot(dx, dy);
    run.player.x = std::clamp(run.player.x + dx / length * 120 * dt, 16.f, float(arena - 16));
    run.player.y = std::clamp(run.player.y + dy / length * 120 * dt, 16.f, float(arena - 16));
    run.walk = std::fmod(run.walk + dt * 20, 16.f);
    angle_approach(&run.body_angle, std::atan2(dy, dx) + pi / 2, 0);
  }
  run.aim_angle = std::atan2(in.y - camera_y(*this) - run.player.y, in.x - camera_x(*this) - run.player.x) + pi / 2;
  run.cooldown = std::max(0.f, run.cooldown - dt);
  run.spread = std::max(0.f, run.spread - dt);
  // The frame callback writes AutoRifle and 30 rounds back on every Survival frame.
  if ((in.fire || in.click) && run.cooldown <= 0) {
    const float angle = run.aim_angle - pi / 2 - .25f;
    vec2f_t muzzle{run.player.x + std::cos(angle) * 12, run.player.y + std::sin(angle) * 12};
    projectile_spawn(&muzzle, run.aim_angle + ((crt_rand() % 200) - 100) * run.spread * .001f, 2);
    run.cooldown = .117f;
    run.spread += .07f;
    play_sound(Sound::Shot);
  }
  update_creatures(*this, dt);
  update_shots(*this, dt);
  // The Survival arm at 0x41ccxx locks weapon 2 and emits a pair every quarter second.
  run.next_spawn -= dt;
  while (run.next_spawn < 0) {
    run.next_spawn += .25f;
    effect_color_t tint{std::min(1.f, run.seconds / 120 + .3f), std::min(1.f, 10 / run.seconds + .3f),
                        std::clamp(std::sin(run.seconds * .1f) + .3f, 0.f, 1.f), 1};
    vec2f_t right{arena + 64, arena * .5f + std::cos(run.seconds) * 256};
    vec2f_t left{-64, arena * .5f + std::sin(run.seconds) * 256};
    creature_spawn(&right, &tint, 1);
    creature_spawn(&left, &tint, 1);
  }
  if (run.health <= 0) {
    screen = Screen::Death;
    std::printf("1.4.0 death %d kills %.2f seconds\n", run.kills, run.seconds);
  }
}
} // namespace freeware
