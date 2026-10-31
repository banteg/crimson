// Minimal host for stepping the same combat bodies linked into both clients.
#include "../freeware/game.h"
#include "freeware_level.h"
#include <cstdio>
#include <cstdlib>
#include <cstring>
namespace freeware {
void play_sound(Sound) {}
void play_original_sample(int) {}
} // namespace freeware
extern freeware::Game *freeware_frame_game;
extern "C" game_mode_id_t config_game_mode;
static freeware::Game game;
extern "C" void combat_reset(unsigned seed) {
  std::memset(player_state_table, 0, sizeof(player_state_table));
  freeware_rainbow_enabled = freeware_rainbow_armed = freeware_secret_weapon_unlocked = 0;
  game = freeware::Game{};
  game.survival = true;
  game.start();
  auto &p = player_state_table[0].freeware;
  p.weapon = 2;
  p.ammo = p.clip_size = 30; // The combat fixtures start after the Survival weapon lock.
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
float combat_frame_fields[28];
struct CapturedQuad {
  char name[16];
  float x, y, w, h, angle;
  effect_color_t color;
};
CapturedQuad combat_frame_quads[128];
int combat_frame_blends[128], combat_frame_label_positions[64];
struct CapturedLabel {
  char text[160];
  float x, y, scale;
  effect_color_t color;
};
CapturedLabel combat_frame_labels[64];
int combat_frame_label_count;
int combat_frame_quad_count;
float combat_level_fields[22];
unsigned char combat_frame_flags[8];
void combat_frame_start(int mode, int count, int phase, int flags) {
  std::memset(player_state_table, 0, sizeof(player_state_table));
  freeware_rainbow_enabled = freeware_rainbow_armed = freeware_secret_weapon_unlocked = 0;
  game = freeware::Game{};
  game.survival = mode == 2;
  game.two_players = count == 2;
  game.start();
  for (auto &record : player_state_table) {
    record.freeware.weapon = mode == 2 ? 2 : 1;
    record.freeware.ammo = record.freeware.clip_size = mode == 2 ? 30.f : 10.f;
  }
  freeware_current_map->clear();
  freeware_current_map->start = {0, 0};
  game.level_mode = mode > 2 ? mode : 0;
  game.editor_light = .8f;
  game.editor_alpha = .7f;
  game.editor_radius = 50;
  if (mode == 4) {
    freeware_level_object brush{};
    brush.width = 32;
    brush.height = 24;
    brush.texture = 999;
    game.brushes.push_back({"arrow", brush});
  }
  game.enter_state(phase);
  game.active_run = phase != 1;
  game.state_since = flags & 512 ? 2.01f : 5;
  game.menu_music_pending = true;
  if (flags >= 4096) {
    game.birthday = flags & 4096;
    game.memorial = flags & 8192;
    game.christmas = flags & 16384;
    game.solstice = flags & 32768;
    game.assembly_sequence = flags & 65536 ? 8 : 0;
    game.state_since = 2;
    game.menu_music_pending = false;
    if (flags & 131072)
      game.screen = freeware::Screen::Online;
    if (flags & 262144) {
      game.screen = freeware::Screen::Options;
      game.calibration = 0;
    }
    if (flags & 524288) {
      game.screen = freeware::Screen::Options;
      game.rebind = 0;
    }
  }
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
    game.actor(i).cooldown = flags & 1024 ? 0.f : .8f;
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
  in.relative = true;
  // Absolute host coordinates may differ from the recovered virtual cursor after a reset.
  in.x = 310;
  in.y = 169;
  if (input & 4096) {
    in.dx = 43;
    in.dy = -17;
  }
  in.ctrl = input & 8192;
  in.escape = input & 1;
  in.level_up = input & 2;
  in.accept = input & 4;
  in.up = input & 8;
  in.fire = input & 16;
  in.next = input & 32;
  in.previous = input & 64;
  in.backspace = input & 128;
  if (input & 256)
    in.text = "x";
  if (input & 512) {
    in.level_pressed.set(3);
    in.level_pressed.set(0xcd);
    in.level_down.set(0x2a);
    in.level_down.set(0xc9);
    in.level_down.set(0xd2);
    in.level_pressed.set(0x2e);
  }
  if (input & 1024) {
    in.level_pressed.set(0x39);
    in.level_down.set(0x2f);
    in.level_pressed.set(0x14);
  }
  if (input & 2048) {
    in.level_pressed.set(0x11);
    in.perk_button = true;
  }
  game.update(dt, in);
  combat_frame_quad_count = int(game.frame_sprites.size());
  if (combat_frame_quad_count > 128)
    std::abort();
  for (size_t i = 0; i < game.frame_sprites.size(); ++i) {
    auto &out = combat_frame_quads[i];
    const auto &draw = game.frame_sprites[i];
    combat_frame_blends[i] = draw.destination_blend;
    std::snprintf(out.name, sizeof(out.name), "%s", draw.name);
    out.x = draw.x;
    out.y = draw.y;
    out.w = draw.width;
    out.h = draw.height;
    out.angle = draw.angle;
    out.color = draw.color;
  }
  combat_frame_label_count = int(game.frame_labels.size());
  if (combat_frame_label_count > 64)
    std::abort();
  for (size_t i = 0; i < game.frame_labels.size(); ++i) {
    const auto &label = game.frame_labels[i];
    auto &out = combat_frame_labels[i];
    combat_frame_label_positions[i] = (int)label.preceding_sprites;
    std::snprintf(out.text, sizeof(out.text), "%s", label.text.c_str());
    out.x = label.x;
    out.y = label.y;
    out.scale = label.scale;
    out.color = label.color;
  }
  auto &level = *freeware_current_map;
  auto &layer = level.layers[1];
  float editor[] = {float(game.editor_brush),
                    float(game.editor_layer),
                    game.editor_rotation,
                    game.editor_light,
                    game.editor_alpha,
                    game.editor_radius,
                    game.editor_offset.x,
                    game.editor_offset.y,
                    level.start.x,
                    level.start.y,
                    float(level.flag),
                    float(layer.size()),
                    float(level.triggers.size())};
  std::copy(std::begin(editor), std::end(editor), combat_level_fields);
  if (layer.size()) {
    const auto &o = *layer.begin[0];
    float stamp[] = {o.position.x,   o.position.y, o.rotation, o.width,  o.height,
                     float(o.flags), o.color.r,    o.color.g,  o.color.a};
    std::copy(std::begin(stamp), std::end(stamp), combat_level_fields + 13);
  }
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
               game.state_since,
               float(game.run.kills),
               float(game.scores().size()),
               float(game.screen == freeware::Screen::Scores),
               float(game.screen == freeware::Screen::Options),
               float(game.selected),
               float(game.name.size())};
  std::copy(std::begin(f), std::end(f), combat_frame_fields);
  std::copy(std::begin(game.random_flags), std::end(game.random_flags), combat_frame_flags);
  return game.frame_state();
}
}

extern "C" {
vec2f_t combat_wall_result;
int combat_wall(float x, float y, float dx, float dy, int count) {
  freeware_level_object walls[] = {{{40, 50}, 0, 20, 15}, {{60, 35}, 0, 10, 30}};
  freeware_level_object *entries[] = {&walls[0], &walls[1]};
  freeware_level_map map = {};
  map.layers[1].begin = entries;
  map.layers[1].end = entries + count;
  combat_wall_result = {x, y};
  vec2f_t delta = {dx, dy};
  return map.move_with_collision(&combat_wall_result, &delta, 8);
}
}

extern "C" bool combat_level_file(const char *path, bool load) {
  freeware_frame_game = &game;
  bool ok = load ? freeware_current_map->load(path) : freeware_current_map->save(path);
  freeware_frame_game = nullptr;
  return ok;
}

// Capture the same ordered submissions consumed by Display::frame_art, before rasterization.
extern freeware::Game *freeware_frame_game;
extern const freeware::Input *freeware_frame_input;
extern float freeware_frame_delta;
extern "C" {
void gameplay_render_hud();
extern int config_player_count;
extern game_mode_id_t config_game_mode;
struct UiDrawCapture {
  char value[384];
  int label, filter, blend;
  float x, y, width, height, angle, uv[4], scale, color[4];
};
UiDrawCapture combat_ui_draws[512];
float combat_ui_result[4];
}
static int capture_ui() {
  int n = 0;
  size_t sprite = 0;
  auto emit = [&](const char *value, bool label, unsigned filter, unsigned blend, float x, float y, float w,
                  float h, float angle, freeware::UiUv uv, float scale, effect_color_t color) {
    if (n == 512)
      std::abort();
    auto &out = combat_ui_draws[n++];
    out = {};
    std::snprintf(out.value, sizeof(out.value), "%s", value);
    out.label = label;
    out.filter = filter;
    out.blend = blend;
    out.x = x;
    out.y = y;
    out.width = w;
    out.height = h;
    out.angle = angle;
    out.uv[0] = uv.u;
    out.uv[1] = uv.v;
    out.uv[2] = uv.s;
    out.uv[3] = uv.t;
    out.scale = scale;
    out.color[0] = color.r;
    out.color[1] = color.g;
    out.color[2] = color.b;
    out.color[3] = color.a;
  };
  auto quad = [&]() {
    const auto &q = game.frame_sprites[sprite++];
    emit(q.name, false, q.filter, q.destination_blend, q.x, q.y, q.width, q.height, q.angle, q.uv, 0, q.color);
  };
  for (const auto &t : game.frame_labels) {
    while (sprite < t.preceding_sprites)
      quad();
    emit(t.text.c_str(), true, 0, 0, t.x, t.y, 0, 0, 0, {}, t.scale, t.color);
  }
  while (sprite < game.frame_sprites.size())
    quad();
  return n;
}
extern "C" int combat_ui_hud(int mode, int count, int variant) {
  game = freeware::Game{};
  freeware_frame_game = &game;
  config_game_mode = static_cast<game_mode_id_t>(mode);
  config_player_count = count;
  game.two_players = count == 2;
  game.enter_state(variant & 2 ? 6 : 3);
  game.active_run = !(variant & 4);
  game.run.pending = variant & 1;
  game.run.perks[11] = variant & 1;
  game.run.seconds = 13.875f;
  game.run.experience = variant & 4 ? 12 : 146;
  game.hud_xp_timer = variant & 2 ? .25f : 0;
  frame_dt = .03125f;
  current_player_index = 0;
  for (int i = 0; i < 2; ++i) {
    auto &p = player_state_table[i].freeware;
    p.health = game.actor(i).health = i ? (variant & 2 ? 0.f : 37.f)
                                        : (variant & 4   ? 0.f
                                           : variant & 1 ? 180.f
                                                         : 75.f);
    p.ammo = i ? 2.5f : 7.75f;
    p.clip_size = i ? 12.f : 45.f;
    p.reload = i ? -.5f : variant & 2 ? 2.2f : .625f;
    p.reload_duration = 1.25f;
    p.displayed_experience = 30;
    p.experience = game.run.experience;
    p.weapon = i ? 2 : 1;
  }
  gameplay_render_hud();
  combat_ui_result[0] = game.run.seconds;
  combat_ui_result[1] = game.hud_xp_timer;
  combat_ui_result[2] = (float)player_state_table[0].freeware.displayed_experience;
  combat_ui_result[3] = (float)current_player_index;
  freeware_frame_game = nullptr;
  return capture_ui();
}
extern "C" unsigned char game_highscores_update(), game_credits_update(), freeware_overlay_begin();
extern "C" void game_show_message();
extern "C" int combat_ui_page(int kind, int ticks, int flags, int board) {
  game = freeware::Game{};
  freeware::Input in;
  freeware_frame_game = &game;
  freeware_frame_input = &in;
  freeware_frame_delta = .125f;
  game.two_players = board & 1;
  game.survival = board & 2;
  config_player_count = game.players();
  config_game_mode = static_cast<game_mode_id_t>(game.survival ? 2 : 1);
  game.enter_state(7);
  if (kind == 1)
    game.screen = freeware::Screen::Credits;
  if (kind == 2)
    game.screen = freeware::Screen::Scores;
  freeware_simulation_clock = 4.f + ticks * .0625f;
  game.state_since = 4;
  game.transition_pending = flags & 1;
  game.transition_alpha = flags & 2 ? .5f : flags & 64 ? .04f : 1.f;
  game.perk_transparent = flags & 4;
  in.click = flags & 8;
  in.space_pressed = flags & 16;
  in.escape = flags & 32;
  game.mouse_dy = flags & 128 ? 8.f : 0.f;
  in.arrow_down = flags & 256;
  in.arrow_up = flags & 512;
  game.score_scroll = 3;
  game.cursor_x = 312;
  game.cursor_y = 148;
  game.message = "A message\non two lines.";
  for (int i = 0; i < 4; ++i) {
    freeware::Score entry{};
    entry.name = i == 1 ? "Gunner" : "Other";
    entry.seconds = 160 - i * 7;
    entry.experience = 2700 - i * 13;
    game.scores().push_back(entry);
  }
  game.last_score = game.scores()[1];
  game.invalid_scores[board] = flags & 1024;
  if (kind == 0)
    game_show_message();
  else if (kind == 1)
    game_credits_update();
  else if (kind == 2)
    game_highscores_update();
  else
    freeware_overlay_begin();
  combat_ui_result[0] = frame_dt;
  combat_ui_result[1] = game.state_since;
  combat_ui_result[2] = game.transition_alpha;
  combat_ui_result[3] = (float)game.frame_state();
  freeware_frame_game = nullptr;
  freeware_frame_input = nullptr;
  return capture_ui();
}
extern "C" void perk_selection_screen_update();
extern "C" unsigned char perk_choice_flags[48];
extern "C" int combat_ui_perk(int id, int flags) {
  game = freeware::Game{};
  freeware::Input in;
  game.two_players = flags & 2;
  game.run.pending = 2;
  game.run.perks[25] = flags & 1;
  game.run.perks[id] += bool(flags & 4);
  game.open_perks();
  std::fill_n(perk_choice_flags, 48, 0);
  perk_choice_flags[id] = 1;
  perk_choice_flags[id == 1 ? 2 : 1] = 1;
  game.run.choices = {1, id == 1 ? 2 : id};
  game.perk_hover = flags & 32 ? -1 : id;
  game.cursor_x = flags & 8 ? 430 : flags & 64 ? 295 : 100;
  game.cursor_y = flags & 8 ? 15 : 90 + int(id != 1) * 20;
  game.state_since = 4;
  freeware_simulation_clock = 4.625f;
  game.transition_alpha = 1;
  game.transition_pending = false;
  current_player_index = 0;
  freeware_frame_input = &in;
  freeware_frame_game = &game;
  freeware_frame_delta = .125f;
  in.click = flags & 16;
  in.mouse_fire = flags & 8;
  freeware::seed_random(815);
  perk_selection_screen_update();
  combat_ui_result[0] = (float)game.perk_hover;
  combat_ui_result[1] = (float)game.frame_state();
  combat_ui_result[2] = (float)game.run.pending;
  combat_ui_result[3] = (float)game.run.perks[id];
  freeware_frame_game = nullptr;
  freeware_frame_input = nullptr;
  return capture_ui();
}
