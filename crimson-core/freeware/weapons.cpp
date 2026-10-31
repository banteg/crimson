// SDL input and presentation boundaries for the 1.4.0 player simulation.
#include "freeware_level.h"
#include "game.h"
#include <algorithm>
#include <cmath>

static freeware_level_map arena_level{};
extern "C" {
freeware_level_map *freeware_current_map = &arena_level;
extern int config_player_count, freeware_first_kill_xp;
extern float freeware_berserk_timer, freeware_elapsed_seconds;
extern unsigned char freeware_player_moved;
extern vec2f_t freeware_first_kill_position;
unsigned char console_open_flag, time_scale_active, freeware_rainbow_armed, freeware_rainbow_enabled;
int config_movement_schemes[2], config_aim_schemes[2];
int perk_id_fastloader = 5, perk_id_long_distance_runner = 4, perk_id_sharpshooter = 3, perk_id_fastshot = 14,
    perk_id_ammo_maniac = 11, perk_id_anxious_loader = 22;
float time_scale_factor, bonus_reflex_boost_timer, freeware_fade_time;
vec2f_t freeware_aim_screen, freeware_camera;
unsigned char freeware_key_down[256], freeware_key_edge[256], freeware_mouse_down[3], freeware_mouse_click,
    freeware_pad_fire;
static bool pad_up, pad_down, pad_left, pad_right, aim_left, aim_right;
bool input_move_up_active() { return pad_up; }
bool input_move_down_active() { return pad_down; }
bool input_move_left_active() { return pad_left; }
bool input_move_right_active() { return pad_right; }
bool input_aim_pov_left_active() { return aim_left; }
bool input_aim_pov_right_active() { return aim_right; }
int sfx_play_panned(int sample, float, float) {
  freeware::play_original_sample(sample);
  return 0;
}
static freeware::Game *player_game;
void fx_queue_add_shell(const vec2f_t *p) {
  if (player_game->shell_marks && player_game->pending_shells.size() < 31)
    player_game->pending_shells.push_back(*p);
}
void player_update();
}

namespace freeware {
void Game::step_player(int index, float dt, const Input &in, vec2f_t mouse_world) {
  static const int schemes[] = {2, 1, 3};
  const bool keys[2][5] = {{in.up, in.down, in.left, in.right, in.fire},
                           {in.up2, in.down2, in.left2, in.right2, in.fire2}};
  // The recovered body reads byte-sized DirectInput bindings. These tokens identify
  // the two input rows after SDL applies the configured scancodes.
  for (int i = 0; i < 2; ++i) {
    for (int j = 0; j < 5; ++j) {
      unsigned char token = 32 + i * 5 + j;
      player_state_table[i].freeware.keys[j] = token;
      freeware_key_down[token] = keys[i][j];
      freeware_key_edge[token] = j == 4 && in.fire_edge[i];
    }
  }
  freeware_key_down[0x13] = in.reload;
  freeware_mouse_down[0] = in.mouse_fire || in.click;
  freeware_mouse_down[2] = in.mouse_reload;
  freeware_mouse_click = in.click;
  freeware_pad_fire = in.pad_fire[index];
  float threshold = pad_threshold[index];
  float dx = in.stick_x[index] - pad_center[index].x, dy = in.stick_y[index] - pad_center[index].y;
  pad_up = dy < -threshold;
  pad_down = dy > threshold;
  pad_left = dx < -threshold;
  pad_right = dx > threshold;
  float ax = in.aim_x[index], ay = in.aim_y[index];
  int pov = std::hypot(ax, ay) < threshold || (ax == 0 && ay == 0)
                ? -1
                : int(std::atan2(ax, -ay) * 5729.5779513 + 36000.5) % 36000;
  aim_left = pov == pad_left_pov[index];
  aim_right = pov == pad_right_pov[index];
  config_movement_schemes[index] = schemes[movement[index]];
  config_aim_schemes[index] = aiming[index];
  config_player_count = players();
  vec2f_t pointer = in.relative ? vec2f_t{cursor_x, cursor_y} : vec2f_t{in.x, in.y};
  freeware_camera = {pointer.x - mouse_world.x, pointer.y - mouse_world.y};
  if (aiming[index] == 1 && in.relative) {
    freeware_aim_screen = {cursor_x, cursor_y};
  } else if (aiming[index] == 1) {
    if (index == 0 || aiming[0] != 1) {
      radial_cursor.x += mouse_dx;
      radial_cursor.y += mouse_dy;
    }
    freeware_aim_screen = radial_cursor;
  } else
    freeware_aim_screen = pointer;
  current_player_index = index;
  frame_dt = dt;
  console_open_flag = console_open;
  freeware_berserk_timer = run.berserk;
  freeware_elapsed_seconds = run.seconds;
  freeware_first_kill_position = run.first_kill_pos;
  freeware_first_kill_xp = run.first_kill_xp;
  freeware_player_moved = run.moved;
  time_scale_factor = run.speed_scale;
  bonus_reflex_boost_timer = run.slow;
  auto &fighter = actor(index);
  auto &p = player_state_table[index].freeware;
  p.position = fighter.player;
  p.health = fighter.health;
  p.cooldown = fighter.cooldown;
  p.spread = fighter.spread;
  p.aim_heading = fighter.aim_angle;
  if (!index)
    p.experience = run.experience;
  player_game = this;
  player_update();
  player_game = nullptr;
  if (aiming[index] == 1)
    radial_cursor = freeware_aim_screen;
  if (aiming[index] == 1 && in.relative) {
    cursor_x = radial_cursor.x;
    cursor_y = radial_cursor.y;
  }
  if (!index)
    run.experience = p.experience;
  run.speed_scale = time_scale_factor;
  run.moved = freeware_player_moved != 0;
  run.first_kill_xp = freeware_first_kill_xp;
  fighter.player = p.position;
  fighter.body_angle = p.heading;
  fighter.aim_angle = p.aim_heading;
  fighter.walk = p.walk_phase;
  fighter.cooldown = p.cooldown;
  fighter.spread = p.spread;
}
} // namespace freeware
