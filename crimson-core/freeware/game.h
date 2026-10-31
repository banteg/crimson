#pragma once

#include "crimsonland_types.h"
#include <array>
#include <cstdint>
#include <string>
#include <vector>

namespace freeware {
constexpr int width = 1024, height = 768, arena = 1024;
enum class Screen { Menu, Playing, Dying, Death, Perks, Message, Scores, Credits, Options, Online };
enum class Sound {
  Shot,
  Hit,
  Die,
  Attack,
  Pistol,
  Shotgun,
  Plasma,
  Rocket,
  Flame,
  Reload,
  Bonus,
  Level,
  Explosion,
  Count
};
enum class Bonus { Fire, Freeze, Weapon, Nuke, Shield, Time };
struct Pickup {
  vec2f_t pos{};
  Bonus kind{};
  float time{};
  int weapon{};
};
struct Input {
  float x = width / 2, y = height / 2;
  bool fire{}, click{}, up{}, down{}, left{}, right{};
  bool previous{}, next{}, accept{}, escape{}, backspace{};
  bool up2{}, down2{}, left2{}, right2{}, fire2{}, reload{}, level_up{};
  bool ctrl{};
  int key{};
  float stick_x[2]{}, stick_y[2]{}, aim_x[2]{}, aim_y[2]{};
  bool pad_fire[2]{};
  std::string text;
};
struct Corpse {
  vec2f_t position;
  float size, heading;
  effect_color_t color;
};
struct Fighter {
  vec2f_t player{512, 512};
  float health = 100, body_angle{}, aim_angle{}, walk{}, cooldown = .8f;
  float spread = 1, move_speed{}, shield{}, locked_aim{};
  bool firing{};
};
struct Run : Fighter {
  Fighter partner;
  float seconds{}, next_spawn{}, freeze{}, slow{}, speed_scale = 1, exp_clock{}, jinx{}, berserk{}, plague_time{},
                                                   bomb_age = -1;
  vec2f_t bomb_pos{}, first_kill_pos{-100, -100};
  bool moved{}, final_revenge{};
  int first_kill_xp = -1, level = 1, pending{}, infections{};
  int frames{};
  float min_fps = 10000, max_fps{};
  Pickup pickup;
  std::array<int, 48> perks{};
  std::vector<int> choices;
  std::array<int, 64> shot_owner{}, rocket_owner{};
  int kills{}, hits{}, experience{};
};
struct Score {
  std::string name;
  float seconds;
  int kills{}, experience{};
  float min_fps{}, average_fps{}, max_fps{}, version = 1.4f;
};
struct Game {
  Screen screen = Screen::Menu;
  Run run;
  std::vector<Corpse> decals;
  float menu_clock{}, cursor_x = 320, cursor_y = 140;
  int selected{}, generation{};
  float death_clock{};
  std::array<std::vector<Score>, 4> rankings;
  std::array<bool, 4> invalid_scores{};
  int tips_sequence{};
  bool secret_hints{};
  std::string save_dir;
  std::vector<Score> &scores() { return rankings[(survival ? 2 : 0) + int(two_players)]; }
  const std::vector<Score> &scores() const { return rankings[(survival ? 2 : 0) + int(two_players)]; }
  Fighter &actor(int i) { return i ? run.partner : static_cast<Fighter &>(run); }
  const Fighter &actor(int i) const { return i ? run.partner : static_cast<const Fighter &>(run); }
  int players() const { return two_players ? 2 : 1; }
  int configuring{}, rebind = -1;
  int movement[2]{0, 0}, aiming[2]{0, 2};
  int keys[2][5]{{26, 22, 4, 7, 43}, {82, 81, 80, 79, 228}};
  bool show_fps{}, effects = true, smooth = true;
  float mouse_dx{}, mouse_dy{}, fps{};
  std::string option(int row) const;
  void load_options();
  void save_options() const;
  bool survival{}, paused{}, quit{}, two_players{}, music_enabled = true;
  const char *notice = nullptr;
  std::string name, message;
  void update(float dt, const Input &input);
  void start();
  void step_player(int index, float dt, const Input &in);
  void fire_weapon(int index);
  void spawn_career();
  void kill(int slot, int owner);
  void update_career(float dt);
  void open_perks();
  void choose_perk(int choice);
  void load_scores();
  void record_score();
  int next_level_xp() const;

  void tick(float dt, const Input &input);
  void finish_death(float dt);
};
extern const char *const main_labels[8];
bool decode_scores(std::vector<uint8_t>, int board, std::vector<Score> &);
std::vector<uint8_t> encode_scores(const std::vector<Score> &, int board);
struct MenuRow {
  const char *label;
  float x, y;
};
MenuRow menu_row(const Game &game, int row);
int menu_hover(const Game &game);
extern "C" float player_heading_approach_target(float);
float camera_x(const Game &game);
float camera_y(const Game &game);
void play_sound(Sound sound);
void seed_random(unsigned seed);
const char *perk_name(int);
const char *perk_description(int);
} // namespace freeware
extern "C" {
int crt_rand();
int creature_alloc_slot();
int creature_find_nearest(const vec2f_t *);
int creature_find_in_radius(const vec2f_t *, float);
int plaguebearer_spread_infection(int);
int projectile_spawn(const vec2f_t *, float, int);
void weapon_assign_player(int, int);
char *weapon_name_get(int);
extern player_state_t player_state_table[2];
extern unsigned char freeware_secret_weapon_unlocked;
extern int current_player_index, creature_spawned_count, plaguebearer_infection_count;
extern float bonus_fire_bullets_timer;
extern creature_t creature_pool[512];
extern projectile_pool_t projectile_pool;
extern secondary_projectile_pool_t secondary_projectile_pool;
extern int highscore_record_shots_fired;
}
