// Shared combat and the Survival branches of crimson.exe 1.4.0. Addresses below are VAs in the pinned image.
#include "game.h"
#include <algorithm>
#include <cmath>
#include <cstddef>
#include <cstdio>
#include <cstring>

extern "C" {
creature_t creature_pool[512];
projectile_pool_t projectile_pool;
secondary_projectile_pool_t secondary_projectile_pool;
particle_t particle_pool[128];
char freeware_text_buffer[256];
unsigned char freeware_secret_weapon_unlocked;
int plaguebearer_infection_count;
float frame_dt, bonus_fire_bullets_timer, freeware_elapsed_seconds;
game_mode_id_t config_game_mode = static_cast<game_mode_id_t>(2);
int creature_spawned_count;
int creature_spawn(const vec2f_t *, const effect_color_t *, int);
int highscore_record_shots_fired, highscore_record_hits;
float freeware_simulation_clock, freeware_hit_sound_timer, bonus_freeze_timer;
sprite_effect_t sprite_effect_pool[384];
int current_player_index;
player_state_t player_state_table[2];
float player_heading_approach_target(float);
void creature_reset_all();
int creature_find_in_radius(const vec2f_t *, float);
int projectile_spawn(const vec2f_t *, float, int);
float angle_approach(float *, float, float);
}

namespace freeware {
constexpr float pi = 3.14159265f;
static_assert(sizeof(creature_t) == 0x80 && sizeof(projectile_t) == 0x34);
static_assert(sizeof(freeware_player_t) == 0x188 && sizeof(player_state_t) == 0x188);
static_assert(offsetof(freeware_player_t, aim) == 0x4c && offsetof(freeware_player_t, perks) == 0x94);
static_assert(sizeof(freeware_perk_entry_t) == 20 && sizeof(particle_t) == 0x38);

static vec2f_t camera_subject(const Game &g) {
  if (!g.two_players || g.run.partner.health <= 0)
    return g.run.player;
  if (g.run.health <= 0)
    return g.run.partner.player;
  return {(g.run.player.x + g.run.partner.player.x) * .5f, (g.run.player.y + g.run.partner.player.y) * .5f};
}
float camera_x(const Game &g) { return std::clamp(width * .5f - camera_subject(g).x, float(width - arena), 0.f); }
float camera_y(const Game &g) {
  return std::clamp(height * .5f - camera_subject(g).y, float(height - arena), -1.f);
}

static unsigned rng = 1;
void seed_random(unsigned seed) { rng = seed; }
extern "C" int crt_rand() {
  rng = rng * 214013u + 2531011u;
  return (rng >> 16) & 0x7fff;
}

void Game::start() {
  // Reset path 0x408e90 calls 0x408440 and clears all 64 shots and 512 creatures.
  run = Run{};
  current_player_index = plaguebearer_infection_count = 0;
  freeware_secret_weapon_unlocked = 0;
  config_game_mode = static_cast<game_mode_id_t>(survival ? 2 : 1);
  std::memset(player_state_table, 0, sizeof(player_state_table));
  for (int i = 0; i < players(); ++i) {
    auto &w = player_state_table[i].freeware;
    w.weapon = survival ? 2 : 1;
    w.ammo = w.clip_size = survival ? 30.f : 10.f;
    actor(i).player.x += i * 80;
  }
  std::memset(particle_pool, 0, sizeof(particle_pool));
  std::memset(secondary_projectile_pool, 0, sizeof(secondary_projectile_pool));
  creature_reset_all();
  for (int i = 0; i < 512; ++i)
    creature_pool[i].freeware.player = i % players();
  std::memset(projectile_pool, 0, sizeof(projectile_pool));
  highscore_record_shots_fired = highscore_record_hits = 0;
  freeware_hit_sound_timer = 0;
  std::memset(sprite_effect_pool, 0, sizeof(sprite_effect_pool));
  creature_spawned_count = 0;
  freeware_elapsed_seconds = 0;
  bonus_fire_bullets_timer = 0;
  name.clear();
  paused = false;
  screen = Screen::Playing;
  ++generation;
  std::printf("1.4.0 %s start %d\n", survival ? "survival" : "career", generation);
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
      c.pos_x -= std::cos(s.heading - pi / 2) * c.death_timer * dt * 9;
      c.pos_y -= std::sin(s.heading - pi / 2) * c.death_timer * dt * 9;
      if (c.death_timer < 0) {
        g.decals.push_back({c.position, s.size, s.heading - pi / 2, s.color});
        c.active = 0;
      }
      continue;
    }
    if (g.run.freeze > 0 || !c.ai_mode)
      continue;
    // Level 8 and 17 bosses stop to spawn a small alien every four seconds.
    if (c.hit_flash_timer != -1) {
      c.hit_flash_timer += dt;
      if (c.hit_flash_timer > 4) {
        effect_color_t tint{.8f, .8f, .8f, 1};
        auto &child = creature_pool[creature_spawn(&c.position, &tint, 1)];
        child.freeware.size = 30;
        child.freeware.move_speed *= .6f;
        c.hit_flash_timer -= 4;
      }
      if (c.hit_flash_timer > 2.5f)
        continue;
    }
    if (s.player < 0 || s.player >= g.players())
      s.player = 0;
    if (g.two_players && g.actor(s.player).health <= 0)
      s.player = 1 - s.player;
    auto &target = g.actor(s.player);
    const auto p = target.player;
    float distance = std::hypot(p.x - c.pos_x, p.y - c.pos_y);
    if (c.plague_infected || (g.run.perks[12] && distance < 100.f)) {
      c.anim_phase -= dt;
      if (c.anim_phase <= 0) {
        c.anim_phase = .5f;
        c.health -= c.plague_infected ? 15.f : (100 - distance) * .3f;
        if (c.health <= 0) {
          if (c.plague_infected)
            ++plaguebearer_infection_count;
          g.kill(i, 0);
          continue;
        }
      }
    }
    if (c.plague_infected)
      plaguebearer_spread_infection(i);
    float offset = i * 3.7f * pi;
    if (g.run.perks[2])
      offset += (1 - (std::sin(g.run.seconds) * .35f + .5f) * .5f) * pi / 2;
    s.target = {p.x + std::cos(offset) * distance * .85f, p.y + std::sin(offset) * distance * .85f};
    s.target_heading = std::atan2(s.target.y - c.pos_y, s.target.x - c.pos_x) + pi / 2;
    if (c.plague_infected)
      s.target_heading += pi;
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
    if (distance < 30 && s.attack_cooldown <= 0 && target.health > 0) {
      if (target.shield <= 0)
        target.health -= s.contact_damage;
      if (g.run.perks[10] && c.health < 150 && plaguebearer_infection_count < 50)
        c.plague_infected = 1;
      s.attack_cooldown += 1;
      if (s.size <= 30) {
        c.health = 0;
        c.death_timer -= dt;
      }
      play_sound(Sound::Attack);
    }
  }
}

// These callbacks are synchronous during combat, just as the original global pools are.
static Game *combat_game;
extern "C" void freeware_blood(const vec2f_t *pos) {
  if (combat_game->marks.size() < 128)
    combat_game->marks.push_back({*pos, 16, 0, false});
}
extern "C" void freeware_shard(const vec2f_t *pos, float size, float rotation) {
  if (combat_game->marks.size() < 128)
    combat_game->marks.push_back({*pos, size, rotation, true});
}
extern "C" void freeware_combat_sound(int id, float) {
  if (id == 31)
    freeware_hit_sound_timer = 1; // 0x405760 starts the combat music.
  else
    play_original_sample(id);
}
extern "C" void creature_handle_death(int id, int owner, unsigned char corpse) {
  combat_game->kill(id, owner, corpse != 0);
}
void Game::update_projectiles(float dt) {
  combat_game = this;
  frame_dt = dt;
  bonus_freeze_timer = run.freeze;
  projectile_update();
  run.hits = highscore_record_hits;
  combat_game = nullptr;
}

void Game::tick(float dt, const Input &in) {
  if (dt > 0) {
    ++run.frames;
    run.min_fps = std::min(run.min_fps, 1 / dt);
    run.max_fps = std::max(run.max_fps, 1 / dt);
  }
  run.seconds += dt;
  freeware_elapsed_seconds = run.seconds;
  run.freeze = std::max(0.f, run.freeze - dt);
  run.slow = std::max(0.f, run.slow - dt);
  bonus_fire_bullets_timer = std::max(0.f, bonus_fire_bullets_timer - dt);
  run.speed_scale = run.slow > 0 ? std::max(.3f, run.speed_scale - dt) : std::min(1.f, run.speed_scale + dt * .8f);
  if (run.perks[15])
    run.speed_scale = std::min(.85f, run.speed_scale);
  dt *= run.speed_scale;
  frame_dt = dt;
  freeware_simulation_clock += dt;
  current_player_index = 0;
  update_creatures(*this, dt);
  update_projectiles(dt);
  for (int i = 0; i < players(); ++i)
    step_player(i, dt, in);
  current_player_index = 0;
  if (!survival)
    update_career(dt);
  // The Survival arm at 0x41cc55 locks weapon 2 and emits a pair every quarter second.
  run.next_spawn -= dt * players();
  while (run.next_spawn < 0) {
    if (!survival) {
      run.next_spawn = std::max(.01f, run.next_spawn + 1 - run.experience / 60000.f);
      spawn_career();
      continue;
    }
    run.next_spawn += .25f;
    effect_color_t tint{std::min(1.f, run.seconds / 120 + .3f), std::min(1.f, 10 / run.seconds + .3f),
                        std::clamp(std::sin(run.seconds * .1f) + .3f, 0.f, 1.f), 1};
    vec2f_t right{arena + 64, arena * .5f + std::cos(run.seconds) * 256};
    vec2f_t left{-64, arena * .5f + std::sin(run.seconds) * 256};
    creature_spawn(&right, &tint, 1);
    creature_spawn(&left, &tint, 1);
  }
  if (!two_players && !survival && run.health <= 0 && run.plague_time < 1 &&
      (run.experience == 6 || run.experience == 66 || run.experience == 666 || run.experience == 6666)) {
    run.health = 1;
    run.plague_time += dt * 10;
    freeware_secret_weapon_unlocked = 1;
    weapon_assign_player(0, 17);
  }
  if (run.health <= 0 && (!two_players || run.partner.health <= 0)) {
    run.health = 0;
    if (run.perks[23]) {
      run.bomb_pos = run.player;
      run.bomb_age = 0;
      run.final_revenge = true;
      play_sound(Sound::Explosion);
    }
    death_clock = 0;
    screen = Screen::Dying;
    std::printf("1.4.0 death %d kills %.2f seconds\n", run.kills, run.seconds);
  }
}

void Game::finish_death(float dt) {
  // Switch case 6 continues combat without spawning and hands off to case 9 after three seconds.
  frame_dt = dt;
  freeware_simulation_clock += dt;
  update_creatures(*this, dt);
  update_projectiles(dt);
  if (run.final_revenge)
    update_career(dt);
  death_clock += dt;
  if (death_clock >= 3.f) {
    screen = run.cheated ? Screen::Scores : Screen::Death;
    std::puts("1.4.0 name entry");
  }
}
} // namespace freeware
