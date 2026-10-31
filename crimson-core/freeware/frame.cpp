// Bind the shared frame dispatcher to the active SDL game and its input snapshot.
#include "game.h"
#include <algorithm>
#include <cstdio>

freeware::Game *freeware_frame_game;
const freeware::Input *freeware_frame_input;
float freeware_frame_delta;
extern "C" {
unsigned char game_frame_update();
void freeware_playing_stage(), freeware_spawn_edge(), freeware_bomb_advance();
extern int config_player_count;
extern game_mode_id_t config_game_mode;
int perk_id_lean_mean_exp_machine = 6, perk_id_spontaneously_combusteous = 7, perk_id_berserk_attack = 13,
    perk_id_reflex_boosted = 15, perk_id_jinxed = 17, perk_id_evil_eyes = 18, perk_id_final_revenge = 23;
}
namespace freeware {
int Game::frame_state() const {
  switch (screen) {
  case Screen::Playing:
    return 3;
  case Screen::Perks:
    return 4;
  case Screen::Dying:
    return 6;
  case Screen::Message:
    return 7;
  case Screen::Death:
    return 9;
  default:
    return 1;
  }
}
void Game::enter_state(int id) {
  switch (id) {
  case 1:
    screen = Screen::Menu;
    break;
  case 3:
    screen = Screen::Playing;
    break;
  case 4:
    screen = Screen::Perks;
    break;
  case 6:
    screen = Screen::Dying;
    break;
  case 9:
    screen = run.cheated ? Screen::Scores : Screen::Death;
    if (run.cheated)
      active_run = false;
    std::puts("1.4.0 name entry");
    break;
  }
}
void Game::update(float dt, const Input &in) {
  frame_labels.clear();
  decals.clear();
  marks.clear();
  shells.clear();
  if (console_open) {
    console_input(in);
    return;
  }
  if (in.console && screen != Screen::Death) {
    console_open = true;
    command.clear();
    return;
  }
  menu_clock += dt;
  resumed_this_frame = false;
  mouse_dx = in.x - cursor_x;
  mouse_dy = in.y - cursor_y;
  cursor_x = in.x;
  cursor_y = in.y;
  if (dt > 0) {
    fps = 1 / dt;
    if (screen == Screen::Playing) {
      ++run.frames;
      run.min_fps = std::min(run.min_fps, fps);
      run.max_fps = std::max(run.max_fps, fps);
    }
  }
  config_player_count = players();
  config_game_mode = static_cast<game_mode_id_t>(survival ? 2 : 1);
  freeware_frame_game = this;
  freeware_frame_input = &in;
  freeware_frame_delta = dt;
  if (!game_frame_update())
    quit = true;
  freeware_frame_input = nullptr;
  freeware_frame_game = nullptr;
}
void Game::combat_frame(float dt, const Input &in, vec2f_t mouse_world) {
  freeware_frame_game = this;
  freeware_frame_input = &in;
  current_player_index = 0;
  config_player_count = players();
  frame_dt = dt;
  cursor_x = mouse_world.x + camera.x;
  cursor_y = mouse_world.y + camera.y;
  freeware_playing_stage();
  freeware_frame_input = nullptr;
  freeware_frame_game = nullptr;
}
void Game::spawn_career() {
  player_state_table[current_player_index].freeware.experience = run.experience;
  freeware_spawn_edge();
}
void Game::update_bomb(float dt) {
  freeware_frame_game = this;
  frame_dt = dt;
  freeware_bomb_advance();
  apply_bomb_damage(dt);
  freeware_frame_game = nullptr;
}
} // namespace freeware
