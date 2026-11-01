#pragma once

#include "freeware_level.h"
#include <array>
#include <bitset>
#include <cstdint>
#include <string>
#include <vector>

#ifndef FREEWARE_EDITION
#define FREEWARE_EDITION 10400
#endif
#if FREEWARE_EDITION == 10300
#define FREEWARE_VERSION "1.3.0"
#elif FREEWARE_EDITION == 10002
#define FREEWARE_VERSION "1.0.2"
#elif FREEWARE_EDITION == 10400
#define FREEWARE_VERSION "1.4.0"
#else
#error Unsupported freeware edition
#endif

#include "freeware_edition.h"

namespace freeware {
constexpr int width = FREEWARE_EDITION < 10400 ? 640 : 1024, height = width * 3 / 4, arena = 1024;
constexpr int main_row_count = FREEWARE_EDITION == 10002 ? 6 : FREEWARE_EDITION == 10300 ? 7 : 8;
constexpr int option_row_count = FREEWARE_EDITION == 10002 ? 9 : FREEWARE_EDITION == 10300 ? 11 : 12;
constexpr int main_row_top = FREEWARE_EDITION == 10002 ? 220 : 200;
int main_action(int row);
int option_action(int row);
enum class Screen { Menu, Playing, Dying, Death, LevelCleared, Perks, Message, Scores, Credits, Options, Online };
enum class Sound {
  Hit = 0,
  Pistol = 2,
  Die = 3,
  Shot = 7,
  Plasma = 8,
  Attack = 9,
  PlasmaFast = 12,
  Wind = 13,
  Flame = 14,
  Shotgun = 15,
  Reload = 16,
  Level = 17,
  Bonus = 18,
  Berserk = 19,
  Rocket = 20,
  Explosion = 21,
  Burst = 26,
  Drip = 27,
  Decay = 28,
  Count = 29
};
enum class Bonus { None, Fire, Freeze, Weapon, Nuke, Shield, Time };
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
  bool ctrl{}, console{}, mouse_fire{}, bend_time{}, fast_time{}, right_mouse{};
  bool screenshot{}, relative{}, arrow_down{}, arrow_up{}, space_pressed{}, delete_scores{};
  float dx{}, dy{};
  std::bitset<256> level_down, level_pressed;
  int key{};
  float stick_x[2]{}, stick_y[2]{}, aim_x[2]{}, aim_y[2]{};
  bool pad_any[2]{}, pad_fire[2]{}, pad_perk[2]{}, fire_edge[2]{}, mouse_reload{}, perk_button{};
  std::string text;
};
struct TrailDraw {
  const char *texture;
  vec2f_t points[4];
  std::array<effect_color_t, 4> colors;
  unsigned filter, source_blend, destination_blend;
};
struct QueuedImpact {
  const char *effect_id;
  vec2f_t position;
  float width, height, rotation;
  effect_color_t color;
};
struct FxQueues {
  int impact_count{}, blood_count{}, shell_count{}, corpse_count{};
  std::array<QueuedImpact, 64> impacts{};
  std::array<vec2f_t, 64> blood{}, corpse_positions{};
  std::array<vec2f_t, 32> shells{};
  std::array<effect_color_t, 64> corpse_colors{};
  std::array<float, 64> corpse_angles{}, corpse_sizes{};
  std::array<int, 64> corpse_species{};
};
struct UiUv {
  float u = 0, v = 0, s = 1, t = 1;
};
struct UiState {
  const char *texture = "bullet";
  UiUv uv;
  effect_color_t color{1, 1, 1, 1};
  float angle{}, scale = 1;
  unsigned filter = 2, destination_blend = 6, source_blend = 5;
};
struct FrameSprite {
  std::string name;
  float x, y, width, height, angle;
  effect_color_t color;
  UiUv uv{};
  unsigned filter{}, destination_blend{}, source_blend = 5;
};
struct FrameLabel {
  std::string text;
  float x, y, scale;
  effect_color_t color;
  size_t preceding_sprites;
};
struct Fighter {
  vec2f_t player{512, 512};
  float health = 100, body_angle{}, aim_angle{}, walk{}, cooldown = .8f;
  float spread = 1, shield{};
};
struct Run : Fighter {
  Fighter partner;
  float seconds{}, next_spawn{}, freeze{}, slow{}, speed_scale = 1, exp_clock{}, jinx{}, berserk{}, plague_time{},
                                                   bomb_age = -1;
  vec2f_t bomb_pos{}, first_kill_pos{-100, 0};
  bool moved{}, cheated{};
  int first_kill_xp = 0, level = 1, pending{}, infections{};
  float min_fps = 10000, max_fps{};
  Pickup pickup;
  std::array<int, 48> perks{};
  std::vector<int> choices;
  int kills{}, hits{}, experience{};
};
struct Score {
  std::string name;
  int seconds{};
  int kills{}, experience{};
  float min_fps{}, average_fps{}, max_fps{}, version = FREEWARE_EDITION == 10002 ? 1.02f : FREEWARE_EDITION == 10300 ? 1.3f : 1.4f;
};
struct LevelBrush {
  std::string name;
  freeware_level_object object;
};
struct Game {
  Screen screen = Screen::Menu, presented_screen = Screen::Menu;
  int levels_sequence{}, level_mode{}, level_number{}, editor_brush{}, editor_layer{};
  float editor_rotation{}, editor_light = 1, editor_alpha = 1, editor_radius = 20;
  vec2f_t editor_offset{};
  std::vector<LevelBrush> brushes;
  void load_level_brushes();
  void load_next_level();
  Run run;
  FxQueues fx;
  std::vector<FrameSprite> terrain_sprites, actor_sprites, effect_sprites;
  std::vector<FrameLabel> effect_labels;
  std::array<effect_color_t, 4> trail_colors;
  std::vector<TrailDraw> frame_trails;
  std::vector<FrameSprite> terrain_marks;
  int terrain_revision{}, presented_terrain_revision{};
  std::vector<FrameSprite> terrain;
  effect_color_t terrain_clear{};
  void generate_terrain(bool textured = true);
  float cursor_x = 320, cursor_y = 140;
  int selected{}, generation{}, perk_hover{};
  float death_clock{};
  vec2f_t radial_cursor{320, 140}, camera{0, -128}, camera_shake{};
  float camera_timer{}, state_since{};
  unsigned char random_flags[8]{};
  bool transition_pending = true;
  float transition_alpha = 1;
  bool wind_started{}, active_run{}, paused_perks{}, menu_music_pending = true;
  float logo_angle{}, snow_y[width]{};
  bool logo_visible{}, birthday{}, memorial{}, solstice{}, christmas{};
  int assembly_sequence{}, fps_count{}, low_fps_frames{};
  float fps_history[50]{};
  bool smoke = true, shadows = true, screenshot_requested{};
  int screenshot_index{};
  UiState ui;
  float hud_xp_timer{};
  std::vector<FrameSprite> frame_sprites;
  std::vector<FrameLabel> frame_labels;
  float score_scroll{};
  bool score_highlighted{}, scores_closing{};
  Score last_score;
  std::array<std::vector<Score>, 4> rankings;
  std::array<bool, 4> invalid_scores{};
  int tips_sequence{};
  bool secret_hints{}, perk_transparent{};
  std::string save_dir, asset_dir;
  std::vector<Score> &scores() { return rankings[(survival ? 2 : 0) + int(two_players)]; }
  const std::vector<Score> &scores() const { return rankings[(survival ? 2 : 0) + int(two_players)]; }
  Fighter &actor(int i) { return i ? run.partner : static_cast<Fighter &>(run); }
  const Fighter &actor(int i) const { return i ? run.partner : static_cast<const Fighter &>(run); }
  int players() const { return two_players ? 2 : 1; }
  int configuring{}, rebind = -1;
  int movement[2]{0, 0}, aiming[2]{0, 2};
  int keys[2][5]{{26, 22, 4, 7, 43}, {82, 81, 80, 79, 228}};
  bool sound_quiet{}, show_fps{}, safe_mode{}, effects = true, smooth = true, shell_marks{}, direction_arrow = true;
  int calibration = -1;
  vec2f_t pad_center[2]{};
  float pad_threshold[2]{.1f, .1f};
  int pad_left_pov[2]{27000, 27000}, pad_right_pov[2]{9000, 9000};

  float mouse_dx{}, mouse_dy{}, fps{};
  std::string option(int row) const;
  void load_options();
  void save_options() const;
  bool survival{}, paused{}, quit{}, two_players{}, music_enabled = true;
  const char *notice = nullptr;
  std::string name, message, command, update_info;
  std::vector<std::string> console_lines, history;
  int history_index{}, spawn_health = 100;
  bool console_open{}, visit_website{};
  effect_color_t spawn_color{1, 1, 1, 1};
  void console_input(const Input &);

  void update(float dt, const Input &input);
  void reset_gameplay();
  void start();
  void step_player(int index, float dt, const Input &in, vec2f_t mouse_world);
  void spawn_career();
  void kill(int slot, int owner, bool corpse = true);
  void update_bomb(float dt);
  void update_projectiles(float dt);
  void update_creatures(float dt);

  void open_perks();
  void choose_perk(int choice);
  void load_scores();
  void discard_corrupt_score();
  void record_score(float average_fps);
  bool store_scores(const std::vector<Score> &) const;
  bool merge_scores(const std::string &filename);
  int next_level_xp() const;

  int frame_state() const;
  void enter_state(int id);
  void combat_frame(float dt, const Input &in, vec2f_t mouse_world);
  void check_level();
};
extern const char *const main_labels[8], *const online_labels[5];
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
void play_original_sample(int);
void seed_random(unsigned seed);
const char *perk_name(int);
const char *perk_description(int);
// Combat routines can also be stepped outside Game::update. Nested calls restore their caller.
class FrameGameScope {
  Game *previous;

public:
  explicit FrameGameScope(Game &game);
  ~FrameGameScope();
  FrameGameScope(const FrameGameScope &) = delete;
  FrameGameScope &operator=(const FrameGameScope &) = delete;
};
} // namespace freeware
extern "C" {
int crt_rand();
int creature_alloc_slot();
unsigned char creature_spawn_random(const vec2f_t *);
void bonus_spawn_at(const vec2f_t *);
int creature_spawn(const vec2f_t *, const effect_color_t *, int);
int creature_find_nearest(const vec2f_t *);
int creature_find_in_radius(const vec2f_t *, float);
int plaguebearer_spread_infection(int);
int projectile_spawn(const vec2f_t *, float, int);
void weapon_assign_player(int, int);
char *weapon_name_get(int);
extern player_state_t player_state_table[2];
extern unsigned char freeware_secret_weapon_unlocked, freeware_rainbow_armed, freeware_rainbow_enabled;
extern int current_player_index, creature_spawned_count, plaguebearer_infection_count;
extern float bonus_fire_bullets_timer;
extern creature_t creature_pool[512];
extern particle_t particle_pool[128];
int fx_spawn_particle(const vec2f_t *, float, const vec2f_t *, float);
int fx_spawn_particle_slow(const vec2f_t *, float, const vec2f_t *);
extern projectile_pool_t projectile_pool;
extern secondary_projectile_pool_t secondary_projectile_pool;
extern int highscore_record_shots_fired, highscore_record_hits;
extern float frame_dt, freeware_simulation_clock, freeware_hit_sound_timer, bonus_freeze_timer;
extern sprite_effect_t sprite_effect_pool[384];
void projectile_update();
void creature_update_all();
int fx_spawn_sprite(const vec2f_t *, const vec2f_t *, float);
}
