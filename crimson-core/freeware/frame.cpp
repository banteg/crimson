// Bind the shared frame dispatcher to the active SDL game and its input snapshot.
#include "game.h"
#include <algorithm>
#include <cstdio>

freeware::Game *freeware_frame_game;
const freeware::Input *freeware_frame_input;
float freeware_frame_delta;
extern "C" {
void effect_render_all();
unsigned char game_frame_update();
void freeware_playing_stage(), freeware_spawn_edge(), freeware_bomb_advance();
extern int config_player_count;
extern game_mode_id_t config_game_mode;
int perk_id_see_health = freeware_rules::doctor;
int perk_id_lean_mean_exp_machine = freeware_rules::lean_mean_exp, perk_id_spontaneously_combusteous = freeware_rules::combustion, perk_id_berserk_attack = freeware_rules::berserk,
    perk_id_reflex_boosted = freeware_rules::reflex_boosted, perk_id_jinxed = freeware_rules::jinxed, perk_id_evil_eyes = freeware_rules::evil_eyes, perk_id_final_revenge = freeware_rules::final_revenge;
}
namespace freeware {
FrameGameScope::FrameGameScope(Game &game) : previous(freeware_frame_game) { freeware_frame_game = &game; }
FrameGameScope::~FrameGameScope() { freeware_frame_game = previous; }
int Game::frame_state() const {
  switch (screen) {
  case Screen::Playing:
    return 3;
  case Screen::Perks:
    return 4;
  case Screen::LevelCleared:
    return 8;
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
  case 7:
    screen = Screen::Message;
    break;
  case 8:
    screen = Screen::LevelCleared;
    break;
  case 9:
    screen = Screen::Death;
    std::puts(FREEWARE_VERSION " name entry");
    break;
  }
}
void Game::update(float dt, const Input &in) {
  terrain_sprites.clear();
  actor_sprites.clear();
  effect_sprites.clear();
  effect_labels.clear();
  frame_trails.clear();
  frame_sprites.clear();
  frame_labels.clear();
  terrain_marks.clear();
  if (in.console) {
    console_open = !console_open;
    if (console_open)
      command.clear();
  } else if (console_open)
    console_input(in);
  mouse_dx = in.relative ? in.dx : in.x - cursor_x;
  mouse_dy = in.relative ? in.dy : in.y - cursor_y;
  if (dt > 0)
    fps = 1 / dt;
  config_player_count = players();
  config_game_mode = static_cast<game_mode_id_t>(level_mode ? level_mode : survival ? 2 : 1);
  freeware_frame_game = this;
  Input quiet;
  quiet.x = cursor_x;
  quiet.y = cursor_y;
  freeware_frame_input = &in;
  if (console_open) {
    freeware_frame_input = &quiet;
  } else if (screen == Screen::Perks && !run.choices.empty() && (in.previous || in.next || in.accept)) {
    // Keyboard navigation positions the same cursor used by the original mouse hit test.
    selected = std::clamp(selected + int(in.next) - int(in.previous), 0, int(run.choices.size()) - 1);
    quiet = in;
    quiet.relative = false;
    quiet.x = 100;
    quiet.y = 90.f + selected * 20;
    quiet.click |= in.accept;
    freeware_frame_input = &quiet;
  }
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
  effect_render_all();
  freeware_frame_game = nullptr;
}
} // namespace freeware
