// Shared combat and the Survival branches of crimson.exe 1.4.0. Addresses below are VAs in the pinned image.
#include "game.h"
#include <algorithm>
#include <cmath>
#include <cstddef>
#include <cstdio>
#include <cstring>

extern "C" {
int freeware_first_kill_xp, freeware_no_pickup, perk_id_bloody_mess = 1;
unsigned char freeware_player_moved;
vec2f_t freeware_first_kill_position;
extern int freeware_pickup_id, freeware_pickup_weapon;
extern vec2f_t freeware_pickup_position;
extern float freeware_pickup_time;
void freeware_creature_handle_death_body(int, int, unsigned char);
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
float freeware_berserk_timer;
unsigned char freeware_game_active;
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
static_assert(offsetof(freeware_player_t, walk_phase) == 0x7c && offsetof(freeware_player_t, keys) == 0x17c);
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

extern "C" {
unsigned freeware_rng_state = 1;
}
void seed_random(unsigned seed) { freeware_rng_state = seed; }
extern "C" int crt_rand() {
  freeware_rng_state = freeware_rng_state * 214013u + 2531011u;
  return (freeware_rng_state >> 16) & 0x7fff;
}

// terrain_generate (0x40e060) uses the gameplay CRT stream, including on restart.
void Game::generate_terrain() {
  terrain.clear();
  for (bool grass : {true, false}) {
    const int count = arena * arena * (grass ? 700 : 35) / 524288;
    for (int i = 0; i < count; ++i) {
      float angle = (crt_rand() % 314) * .01f;
      float x = float(crt_rand() % (arena + 128) - 64);
      float y = float(crt_rand() % (arena + 128) - 64);
      terrain.push_back({{x, y}, angle, grass});
    }
  }
}
void Game::start() {
  // Reset path 0x408e90 calls 0x408440 and clears all 64 shots and 512 creatures.
  run = Run{};
  current_player_index = plaguebearer_infection_count = 0;
  freeware_rainbow_enabled = freeware_rainbow_armed = freeware_secret_weapon_unlocked = 0;
  radial_cursor = {320, 140};
  config_game_mode = static_cast<game_mode_id_t>(survival ? 2 : 1);
  std::memset(player_state_table, 0, sizeof(player_state_table));
  for (int i = 0; i < players(); ++i) {
    auto &w = player_state_table[i].freeware;
    w.size = 48;
    w.speed_multiplier = 2;
    w.level = 1;
    w.reload_duration = 1;
    w.weapon = survival ? 2 : 1;
    w.ammo = w.clip_size = survival ? 30.f : 10.f;
    actor(i).player.x += i * 80;
  }
  std::memset(particle_pool, 0, sizeof(particle_pool));
  std::memset(secondary_projectile_pool, 0, sizeof(secondary_projectile_pool));
  creature_reset_all();
  for (int i = 0; i < 512; ++i) {
    creature_pool[i].freeware.player = i % players();
    creature_pool[i].ai_mode = 1;
  }
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
  generate_terrain();
  ++generation;
  std::printf("1.4.0 %s start %d\n", survival ? "survival" : "career", generation);
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
void Game::kill(int id, int owner, bool corpse) {
  if (!creature_pool[id].active)
    return;
  Game *previous = combat_game;
  combat_game = this;
  int old = current_player_index;
  current_player_index = owner;
  auto &p = player_state_table[owner].freeware;
  p.position = actor(owner).player;
  p.experience = run.experience;
  p.perks[1] = run.perks[1];
  freeware_first_kill_xp = run.first_kill_xp;
  freeware_first_kill_position = run.first_kill_pos;
  freeware_player_moved = run.moved;
  freeware_pickup_id = run.pickup.time > 0 ? int(run.pickup.kind) : freeware_no_pickup;
  freeware_pickup_time = run.pickup.time;
  bonus_freeze_timer = run.freeze;
  freeware_creature_handle_death_body(id, owner, corpse);
  run.experience = p.experience;
  run.first_kill_pos = freeware_first_kill_position;
  run.first_kill_xp = freeware_first_kill_xp;
  if (run.pickup.time <= 0 && freeware_pickup_time > 0)
    run.pickup = {freeware_pickup_position, static_cast<Bonus>(freeware_pickup_id), freeware_pickup_time,
                  freeware_pickup_weapon};
  if (++run.kills == 1)
    std::puts("1.4.0 first kill");
  current_player_index = old;
  combat_game = previous;
}
extern "C" void creature_handle_death(int id, int owner, unsigned char corpse) {
  combat_game->run.experience = player_state_table[0].freeware.experience;
  combat_game->kill(id, owner, corpse != 0);
  player_state_table[0].freeware.experience = combat_game->run.experience;
}
void Game::update_creatures(float dt) {
  combat_game = this;
  frame_dt = dt;
  bonus_freeze_timer = run.freeze;
  freeware_berserk_timer = run.berserk;
  freeware_game_active = 1;
  for (int i = 0; i < 2; ++i) {
    auto &p = player_state_table[i].freeware;
    p.position = actor(i).player;
    p.health = actor(i).health;
    p.shield = actor(i).shield;
    p.plaguebearer = run.perks[10] > 0;
  }
  player_state_table[0].freeware.experience = run.experience;
  creature_update_all();
  run.experience = player_state_table[0].freeware.experience;
  for (int i = 0; i < players(); ++i)
    actor(i).health = player_state_table[i].freeware.health;
  combat_game = nullptr;
}
void Game::resolve_corpses() {
  for (auto &c : creature_pool) {
    if (!c.active || c.death_timer >= 0)
      continue;
    decals.push_back(
        {c.position, c.freeware.size, c.freeware.heading - (c.freeware.type == 1 ? pi / 2 : 0), c.freeware.color});
    c.active = 0;
  }
}
void Game::update_projectiles(float dt) {
  combat_game = this;
  player_state_table[0].freeware.experience = run.experience;
  frame_dt = dt;
  bonus_freeze_timer = run.freeze;
  projectile_update();
  run.hits = highscore_record_hits;
  combat_game = nullptr;
}

// Gameplay block 0x4183cd..0x418587. Living players act after the existing combat pools.
void Game::combat_frame(float dt, const Input &in, vec2f_t mouse_world) {
  current_player_index = 0;
  frame_dt = dt;
  run.exp_clock -= dt;
  if (run.exp_clock < 0) {
    run.exp_clock = .25f;
    run.experience += run.perks[6] * 10;
  }
  update_creatures(dt);
  update_projectiles(dt);
  for (int i = 0; i < players(); ++i)
    step_player(i, dt, in, mouse_world);
  current_player_index = 0;
  if (!survival)
    check_level();
}

void Game::tick(float dt, const Input &in) {
  if (dt > 0) {
    ++run.frames;
    run.min_fps = std::min(run.min_fps, 1 / dt);
    run.max_fps = std::max(run.max_fps, 1 / dt);
  }
  if (run.perks[15])
    run.speed_scale = std::min(.85f, run.speed_scale);
  dt *= run.speed_scale;
  freeware_simulation_clock += dt;
  combat_frame(dt, in, {in.x - camera_x(*this), in.y - camera_y(*this)});
  // The HUD advances the run clock after simulation, before the mode spawner.
  run.seconds += dt;
  freeware_elapsed_seconds = run.seconds;
  run.freeze = std::max(0.f, run.freeze - dt);
  run.slow = std::max(0.f, run.slow - dt);
  bonus_fire_bullets_timer = std::max(0.f, bonus_fire_bullets_timer - dt);
  update_bomb(dt);
  if (!survival)
    update_career(dt);
  if (survival)
    for (auto &p : player_state_table) {
      p.freeware.weapon = 2;
      p.freeware.ammo = 30;
    }
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
  resolve_corpses();
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
      play_sound(Sound::Explosion);
    }
    death_clock = 0;
    screen = Screen::Dying;
    std::printf("1.4.0 death %d kills %.2f seconds\n", run.kills, run.seconds);
  }
}

void Game::finish_death(float dt) {
  // Switch case 6 continues combat without spawning and hands off to case 9 after three seconds.
  dt *= run.speed_scale;
  frame_dt = dt;
  freeware_simulation_clock += dt;
  update_creatures(dt);
  update_projectiles(dt);
  update_bomb(dt);
  resolve_corpses();
  freeware_simulation_clock += dt * .5f;
  death_clock += dt * 1.5f;
  if (death_clock >= 3.f) {
    screen = run.cheated ? Screen::Scores : Screen::Death;
    std::puts("1.4.0 name entry");
  }
}
} // namespace freeware
