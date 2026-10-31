// Minimal host for stepping the same combat bodies linked into both clients.
#include "../freeware/game.h"
namespace freeware {
void play_sound(Sound) {}
void play_original_sample(int) {}
} // namespace freeware
extern "C" game_mode_id_t config_game_mode;
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
extern "C" void combat_actors(int mode, int perk, int partner, float shield) {
  game.survival = mode == 2;
  game.two_players = true;
  game.run.player = {500, 500};
  game.run.partner.player = {600, 500};
  game.run.health = partner ? 0 : 100;
  game.run.partner.health = 100;
  game.run.shield = shield;
  game.run.perks[perk] = 1;
  player_state_table[0].freeware.perks[perk] = 1;
  config_game_mode = static_cast<game_mode_id_t>(mode);
}
extern "C" void combat_creatures(float dt, float clock, float freeze) {
  freeware_simulation_clock = clock;
  game.run.freeze = freeze;
  game.update_creatures(dt);
}
extern "C" int combat_drop() { return game.run.pickup.time > 0 ? int(game.run.pickup.kind) : -1; }
extern "C" int combat_drop_weapon() { return game.run.pickup.weapon; }
extern "C" int combat_first_xp() { return game.run.first_kill_xp; }
extern "C" void combat_reward(float dt, float freeze, bool corpse) {
  frame_dt = dt;
  game.run.freeze = freeze;
  game.kill(0, 0, corpse);
}
extern "C" void combat_arm(int weapon) {
  game.survival = false;
  config_game_mode = static_cast<game_mode_id_t>(1);
  game.run.health = 4;
  game.run.cooldown = 0;
  game.run.player = {512, 512};
  freeware_secret_weapon_unlocked = freeware_rainbow_armed = freeware_rainbow_enabled = 1;
  auto &w = player_state_table[0].freeware;
  w.ammo = 10;
  w.clip_size = 10;
  w.weapon = weapon;
}
extern "C" void combat_player(float dt, int keys, float x, float y, int whole_frame) {
  frame_dt = dt;
  freeware::Input in;
  in.fire = keys & 1;
  in.right = keys & 2;
  in.down = keys & 4;
  in.left = keys & 8;
  in.up = keys & 16;
  in.x = x + freeware::camera_x(game);
  in.y = y + freeware::camera_y(game);
  if (whole_frame)
    game.combat_frame(dt, in, {x, y});
  else
    game.step_player(0, dt, in, {x, y});
  auto &p = player_state_table[0].freeware;
  p.position = game.run.player;
  p.cooldown = game.run.cooldown;
  p.spread = game.run.spread;
  p.aim_heading = game.run.aim_angle;
}
extern "C" void combat_choose(int id) {
  game.run.pending = 2;
  game.run.choices = {id};
  game.choose_perk(0);
}
extern "C" const char *combat_message() { return game.message.c_str(); }
extern "C" float combat_health() { return game.run.health; }
extern "C" int combat_level() { return game.run.level; }
extern "C" int combat_pending() { return game.run.pending; }
extern "C" {
freeware::ShotDraw combat_draw_capture[24];
int combat_draw(float seconds, int effects) {
  std::vector<freeware::ShotDraw> draws;
  freeware::projectile_draws(draws, {5, -8}, seconds, effects != 0);
  if (draws.size() > 24)
    return -1;
  std::copy(draws.begin(), draws.end(), combat_draw_capture);
  return int(draws.size());
}
}
extern "C" {
freeware::TerrainStamp combat_terrain_capture[1470];
int combat_terrain(unsigned seed) {
  freeware::seed_random(seed);
  game.generate_terrain();
  if (game.terrain.size() != 1470)
    return -1;
  std::copy(game.terrain.begin(), game.terrain.end(), combat_terrain_capture);
  return int(game.terrain.size());
}
}

extern "C" float combat_bomb(float dt, int start) {
  frame_dt = dt;
  if (start) {
    game.run.bomb_age = 0;
    game.run.bomb_pos = {500, 500};
  }
  game.update_bomb(dt);
  return game.run.bomb_age;
}

// Seed the input boundary from a complete PE-format record. All rule decisions
// and output mutations still go through the normal Game::step_player entry.
extern "C" void combat_controls(int index, int count, int movement, int aim, int held, int extra, float dt) {
  auto &p = player_state_table[index].freeware;
  auto &f = game.actor(index);
  game.two_players = count == 2;
  game.movement[index] = movement;
  game.aiming[index] = aim;
  f.player = p.position;
  f.health = p.health;
  f.aim_angle = p.aim_heading;
  f.cooldown = p.cooldown;
  f.spread = p.spread;
  game.run.experience = player_state_table[0].freeware.experience;
  game.run.first_kill_pos = {512, 512};
  game.run.first_kill_xp = 7;
  game.run.seconds = (extra & 256) ? 120 : 7;
  game.run.berserk = (extra & 512) ? 11 : 0;
  game.run.slow = (extra & 1024) ? 1 : 0;
  game.run.speed_scale = .73f;
  game.run.moved = false;
  game.console_open = extra & 2048;
  game.radial_cursor = {310, 169};
  game.mouse_dx = game.mouse_dy = 0;
  freeware::Input in;
  in.x = 310;
  in.y = 169;
  in.up = held & 1;
  in.down = held & 2;
  in.left = held & 4;
  in.right = held & 8;
  in.fire = held & 16;
  in.up2 = held & 32;
  in.down2 = held & 64;
  in.left2 = held & 128;
  in.right2 = held & 256;
  in.fire2 = held & 512;
  in.fire_edge[index] = extra & 1;
  in.fire_edge[1 - index] = extra & 128;
  in.mouse_fire = extra & 2;
  in.click = extra & 4;
  in.reload = extra & 8;
  in.pad_fire[index] = extra & 16;
  in.mouse_reload = extra & 32;
  in.stick_x[index] = int(bool(held & 8)) - int(bool(held & 4));
  in.stick_y[index] = int(bool(held & 2)) - int(bool(held & 1));
  in.aim_x[index] = extra & 64 ? -1 : 1;
  game.step_player(index, dt, in, {312, 177});
}

extern "C" {
float combat_frame_fields[24];
unsigned char combat_frame_flags[8];
void combat_frame_start(int mode, int count, int phase, int flags) {
  game = freeware::Game{};
  game.survival = mode == 2;
  game.two_players = count == 2;
  game.start();
  game.enter_state(phase);
  game.active_run = phase != 1;
  game.state_since = 5;
  freeware_simulation_clock = 5;
  game.run.seconds = 7;
  game.run.next_spawn = flags & 1 ? 0 : 2;
  game.run.pending = flags & 2 ? 1 : 0;
  game.run.freeze = flags & 4 ? .05f : 0;
  game.run.slow = flags & 8 ? .05f : 0;
  game.run.perks[6] = flags & 16 ? 2 : 0;
  game.run.health = flags & 32 ? 0 : 100;
  game.run.partner.health = flags & 64 ? 0 : 100;
  game.run.experience = flags & 128 ? 66 : 0;
  game.run.perks[23] = (flags & 256) != 0;
  for (int i = 0; i < 2; ++i) {
    game.actor(i).player = {512.f + i * 80.f, 512};
    game.actor(i).cooldown = .8f;
    player_state_table[i].freeware.perks[6] = game.run.perks[6];
    player_state_table[i].freeware.perks[23] = game.run.perks[23];
  }
  game.camera = {0, -128};
  game.cursor_x = 310;
  game.cursor_y = 169;
  freeware::seed_random(42);
}
int combat_frame_step(float dt, int input) {
  freeware::Input in;
  in.x = 310;
  in.y = 169;
  in.escape = input & 1;
  in.level_up = input & 2;
  in.accept = input & 4;
  in.up = input & 8;
  in.fire = input & 16;
  game.update(dt, in);
  float f[] = {freeware_simulation_clock,
               frame_dt,
               game.run.seconds,
               game.run.speed_scale,
               game.camera.x,
               game.camera.y,
               game.camera_timer,
               game.camera_shake.x,
               game.camera_shake.y,
               game.run.exp_clock,
               game.run.next_spawn,
               game.run.jinx,
               game.run.freeze,
               game.run.slow,
               game.run.bomb_age,
               game.run.health,
               game.run.partner.health,
               float(game.run.experience),
               float(game.run.pending),
               float(game.active_run),
               game.run.plague_time,
               game.state_since};
  std::copy(std::begin(f), std::end(f), combat_frame_fields);
  std::copy(std::begin(game.random_flags), std::end(game.random_flags), combat_frame_flags);
  return game.frame_state();
}
}
