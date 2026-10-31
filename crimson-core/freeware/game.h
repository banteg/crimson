#pragma once

#include "crimsonland_types.h"
#include <string>
#include <vector>

namespace freeware {
constexpr int width = 1024, height = 768, arena = 1024;
enum class Screen { Menu, Playing, Dying, Death, Scores, Credits, Options, Online };
enum class Sound { Shot, Hit, Die, Attack };
struct Input {
  float x = width / 2, y = height / 2;
  bool fire{}, click{}, up{}, down{}, left{}, right{};
  bool previous{}, next{}, accept{}, escape{}, backspace{};
  std::string text;
};
struct Corpse {
  vec2f_t position;
  float size, heading;
  effect_color_t color;
};
struct Run {
  vec2f_t player{512, 512};
  float health = 100, body_angle{}, aim_angle{}, walk{}, cooldown = .8f;
  float seconds{}, next_spawn{}, spread = 1, move_speed{};
  int kills{}, hits{}, experience{};
};
struct Score {
  std::string name;
  float seconds;
  int kills;
};
struct Game {
  Screen screen = Screen::Menu;
  Run run;
  std::vector<Corpse> decals;
  float menu_clock{}, cursor_x = 320, cursor_y = 140;
  int selected{}, generation{};
  float death_clock{};
  std::vector<Score> scores;
  bool survival{}, paused{}, quit{}, two_players{}, music_enabled = true;
  const char *notice = nullptr;
  std::string name;
  void update(float dt, const Input &input);
  void start();
  void tick(float dt, const Input &input);
  void finish_death(float dt);
};
extern const char *const main_labels[8];
struct MenuRow {
  const char *label;
  float x, y;
};
MenuRow menu_row(const Game &game, int row);
int menu_hover(const Game &game);
float camera_x(const Game &game);
float camera_y(const Game &game);
void play_sound(Sound sound);
void seed_random(unsigned seed);
} // namespace freeware
extern "C" {
extern creature_t creature_pool[512];
extern projectile_pool_t projectile_pool;
extern int highscore_record_shots_fired;
}
