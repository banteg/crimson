// Shared combat and the Survival branches of crimson.exe 1.4.0. Addresses below are VAs in the pinned image.
#include "game.h"
#include <algorithm>
#include <cmath>
#include <cstddef>
#include <cstdio>
#include <cstring>

extern "C" {
int perk_id_radioactive = 12, perk_id_almost_invisible = 2;
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
void player_reset_all();
int creature_find_in_radius(const vec2f_t *, float);
int projectile_spawn(const vec2f_t *, float, int);
float angle_approach(float *, float, float);
}

extern freeware::Game *freeware_frame_game;
extern "C" {
vec2f_t freeware_draw_point[2];
}
namespace freeware {

static_assert(sizeof(creature_t) == 0x80 && sizeof(projectile_t) == 0x34);
static_assert(sizeof(freeware_player_t) == 0x188 && sizeof(player_state_t) == 0x188);
static_assert(offsetof(freeware_player_t, aim) == 0x4c && offsetof(freeware_player_t, perks) == 0x94);
static_assert(offsetof(freeware_player_t, walk_phase) == 0x7c && offsetof(freeware_player_t, keys) == 0x17c);
static_assert(sizeof(freeware_perk_entry_t) == 20 && sizeof(particle_t) == 0x38);

float camera_x(const Game &g) { return g.camera.x; }
float camera_y(const Game &g) { return g.camera.y; }

extern "C" {
unsigned freeware_rng_state = 1;
}
void seed_random(unsigned seed) { freeware_rng_state = seed; }
extern "C" int crt_rand() {
  freeware_rng_state = freeware_rng_state * 214013u + 2531011u;
  return (freeware_rng_state >> 16) & 0x7fff;
}

extern "C" void terrain_generate(unsigned char textured);
void Game::generate_terrain(bool textured) {
  Game *previous = freeware_frame_game;
  freeware_frame_game = this;
  terrain_generate(textured);
  freeware_frame_game = previous;
}
void Game::reset_gameplay() {
  // Reset path 0x408e90 calls 0x408440 and clears all 64 shots and 512 creatures.
  run = Run{};
  active_run = true;
  wind_started = false;
  pending_decals.clear();
  pending_blood.clear();
  pending_shells.clear();
  pending_impacts.clear();
  current_player_index = plaguebearer_infection_count = 0;
  radial_cursor = {320, 140};
  cursor_x = 320;
  cursor_y = 140;
  config_game_mode = static_cast<game_mode_id_t>(level_mode ? level_mode : survival ? 2 : 1);
  player_reset_all();
  for (int i = 0; i < 2; ++i) {
    const auto &p = player_state_table[i].freeware;
    actor(i).player = p.position;
    actor(i).body_angle = p.heading;
    actor(i).aim_angle = p.aim_heading;
    actor(i).walk = p.walk_phase;
  }
  std::memset(particle_pool, 0, sizeof(particle_pool));
  std::memset(secondary_projectile_pool, 0, sizeof(secondary_projectile_pool));
  creature_reset_all();
  for (int i = 0; i < 512; ++i) {
    creature_pool[i].freeware.player = i % players();
    creature_pool[i].ai_mode = config_game_mode != 3;
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
  generate_terrain(config_game_mode < 3 || !freeware_current_map->flag);
}
void Game::start() {
  reset_gameplay();
  ++generation;
  std::printf("1.4.0 %s start %d\n", survival ? "survival" : "career", generation);
}

// These callbacks are synchronous during combat, just as the original global pools are.
static Game *combat_game;
void Game::queue_blood(vec2f_t p) {
  if (pending_blood.size() < 63)
    pending_blood.push_back(p);
}
void Game::queue_impact(const char *texture, vec2f_t center, float w, float h, float rotation,
                        effect_color_t color) {
  if (pending_impacts.size() < 63)
    pending_impacts.push_back({texture, center, w, h, rotation, color});
}
extern "C" void freeware_blood(const vec2f_t *pos) { combat_game->queue_blood(*pos); }
extern "C" void freeware_shard(const vec2f_t *pos, float size, float rotation) {
  combat_game->queue_impact("icemold", *pos, size, size, rotation, {1, 1, 1, 1});
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
  freeware_pickup_id = int(run.pickup.kind);
  freeware_pickup_time = run.pickup.time;
  bonus_freeze_timer = run.freeze;
  freeware_creature_handle_death_body(id, owner, corpse);
  run.experience = p.experience;
  run.first_kill_pos = freeware_first_kill_position;
  run.first_kill_xp = freeware_first_kill_xp;
  if (run.pickup.kind == Bonus::None && freeware_pickup_id != freeware_no_pickup)
    run.pickup = {freeware_pickup_position, static_cast<Bonus>(freeware_pickup_id), freeware_pickup_time,
                  freeware_pickup_weapon};
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
  freeware_game_active = active_run;
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
extern "C" void fx_queue_add_rotated(const vec2f_t *pos, const effect_color_t *color, float angle, float size,
                                     int alien) {
  auto &queue = freeware_frame_game->pending_decals;
  Corpse mark{alien ? 62 : 31, *pos, size, angle, *color};
  if (queue.size() < 63)
    queue.push_back(mark);
  else {
    int slot = crt_rand() % 64;
    if (slot < 63)
      queue[slot] = mark;
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

} // namespace freeware
