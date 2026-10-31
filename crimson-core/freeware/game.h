#pragma once

#include "crimsonland_types.h"
#include <string>

namespace freeware {
constexpr int width = 1024, height = 768, arena = 1024;
enum class Screen { Menu, Playing, Death, Scores, Credits, Options, Online };
enum class Sound { Shot, Hit, Die, Attack };
struct Input {
  float x = width / 2, y = height / 2;
  bool fire{}, click{}, up{}, down{}, left{}, right{};
  bool previous{}, next{}, accept{}, escape{}, backspace{};
  std::string text;
};
struct Run {
  vec2f_t player{512, 512};
  float health = 100, body_angle{}, aim_angle{}, walk{}, cooldown = .8f;
  float seconds{}, next_spawn{}, spread{};
  int kills{}, hits{}, experience{};
};
struct Game {
  Screen screen = Screen::Menu;
  Run run;
  float menu_clock{}, cursor_x = 320, cursor_y = 140;
  int selected{}, generation{}, best_kills{};
  float best_seconds{};
  bool survival{}, paused{}, quit{};
  std::string name;
  unsigned rng = 1;
  void update(float dt, const Input &input);
  void start();
  void tick(float dt, const Input &input);
};
extern const char *const main_labels[8];
const char *menu_label(const Game &game, int row);
int menu_hover(const Game &game);
float camera_x(const Game &game);
float camera_y(const Game &game);
void play_sound(Sound sound);
} // namespace freeware
extern "C" {
extern creature_t creature_pool[512];
extern projectile_pool_t projectile_pool;
extern int highscore_record_shots_fired;
}
