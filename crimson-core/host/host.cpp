#include "api.h"
#include "rules.h"
#include "crimsonland_gameplay.h"
#include "crimsonland_metadata.h"
#include "grim2d_cpp.h"
#include "portable_math.h"
#include <float.h>
#include <math.h>
#include <new>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static PortableInput in;
static PortableConfig cfg;
extern "C" unsigned char portable_preserve_bugs;
unsigned char portable_preserve_bugs;
static PortableCommand commands[16];
static bool ready;
static bool menu_requested;
static char string_arena[65536];
static size_t string_used;
static uint32_t rng;
static uint32_t tick;
// Milliseconds left of the run-down that follows a run's end; native keeps
// simulating while the UI timeline runs out, as Python's `RunDown` does.
static bool running_down;
static int run_down_ms;
static uint32_t output[262144];
static int used;
#include "grim.inc"
extern "C" {
extern IGrim2D_cpp *grim_interface_ptr;
extern int frame_dt_ms, survival_spawn_cooldown, quest_spawn_timeline,
    perk_pending_count;
extern int perk_choice_ids[7];
extern unsigned char time_scale_active, perk_choices_dirty;
extern float time_scale_factor, camera_offset_x, camera_offset_y;
extern game_state_id_t game_state_pending;
extern float bonus_update_phase_accumulator;
extern float perk_jinxed_proc_timer_s;
extern int perk_id_reflex_boosted;
extern float perk_lean_mean_exp_tick_timer_s;
int perk_count_get(int perk_id);
extern unsigned char music_playlist_randomized_latch, music_ready;
extern int music_playlist_entry_count, music_track_intro_id,
    music_track_shortie_monk_id, music_track_crimson_theme_id,
    music_track_crimsonquest_id, music_track_game_playlist, music_track_extra_1;
extern music_playlist_t music_playlist;
extern unsigned char survival_reward_fire_seen, survival_shrinkifier_handout_enabled;
extern int survival_reward_weapon_guard_id, survival_first_kill_count,
    plaguebearer_infection_count, perk_doctor_target_creature_id,
    effect_spawn_detail_skip_counter, quest_stage_banner_timer_ms,
    quest_spawn_stall_timer_ms, highscore_record_shots_hit, creature_kill_count;
extern float camera_shake_offset_x, camera_shake_offset_y;
void portable_reset_data();
void creature_pool_global_init();
void player_state_table_global_init();
void projectile_pool_global_init();
void weapon_table_defaults_global_init();
void bonus_metadata_init();
void perks_init_database();
void gameplay_reset_state();
void gameplay_update_and_render();
void quest_start_selected(int, int);
void perks_generate_choices();
void perk_apply(int);
}
#ifdef CRIMSON_GAME
#include "game.inc"
#endif
static cvar_float_t friendly, transparency, verbose, pad_distance, bodies_fade;
// Device output does not consume gameplay RNG. Music selection keeps the
// recovered implementation.
extern "C" int crt_rand() {
#ifdef CRIMSON_GAME
  // In a session, gameplay RNG belongs to run start and ticks; presentation must
  // not draw it. Between a live run's ticks, the original's frame and menus draw
  // a stream of their own (the tick draws the frame's value, portable_step_many).
  if (game_session && !game_ticking) {
    if (!game_live)
      abort();
    static uint32_t presentation = 1;
    presentation = presentation * 214013u + 2531011u;
    return (presentation >> 16) & 0x7fff;
  }
#endif
  rng = rng * 214013u + 2531011u;
  return (rng >> 16) & 0x7fff;
}
#ifdef CRIMSON_GAME
// Strings made while the engine boots (cvar names among them) outlive runs;
// a run's own strings live in the arena that run start empties.
static bool in_arena(void *p) { return p >= string_arena && p < string_arena + sizeof(string_arena); }
extern "C" void crt_free(void *p) {
  if (!in_arena(p))
    free(p);
}
#else
extern "C" void crt_free(void *) {}
#endif
extern "C" char *strdup_malloc(char *s) {
#ifdef CRIMSON_GAME
  if (game_heap_strings)
    return s ? strdup(s) : nullptr;
#endif
  if (!s)
    return nullptr;
  size_t n = strlen(s) + 1;
  if (n > sizeof(string_arena) - string_used)
    abort();
  char *p = string_arena + string_used;
  memcpy(p, s, n);
  string_used += n;
  return p;
}
#ifndef CRIMSON_GAME
extern "C" char *wrap_text_to_width_alloc(char *s, int) {
  return strdup_malloc(s);
}
#endif
extern "C" int crt_sprintf(char *dst, const char *fmt, ...) {
  va_list v;
  va_start(v, fmt);
  int n = vsprintf(dst, fmt, v);
  va_end(v);
  return n;
}
#ifndef CRIMSON_GAME
extern "C" void console_printf(console_queue_t *, char *, ...) {}
extern "C" int console_input_poll() { return 0; }
extern "C" int play_time_get() { return 0; }
extern "C" unsigned char game_is_full_version() { return 1; }
extern "C" void game_save_status() {}
extern "C" void game_state_set(game_state_id_t s) { game_state_pending = s; }
extern "C" void demo_mode_start() { abort(); }
#endif
#ifndef CRIMSON_GAME
extern "C" void sfx_play(int, float) {}
extern "C" int sfx_play_panned(int, const vec2f_t *, float) { return 0; }
extern "C" int sfx_entry_start_playback(music_entry_t *) { return 1; }
extern "C" void sfx_entry_set_volume(music_entry_t *, float) {}
extern "C" bool input_primary_just_pressed() { return (in.flags & 2) != 0; }
#endif
extern "C" vec2f_t *__stdcall D3DXVec2Normalize(vec2f_t *out,
                                                const vec2f_t *src) {
  // D3DX8's x87 path (0x00455587), including its F32 spills and PC24
  // arithmetic. Preserve input bits near unit length, including signed zero.
  float x = src->x, y = src->y;
  float length_sq = (float)portable_round_pc24(
      portable_round_pc24((double)y * y) + portable_round_pc24((double)x * x));
  float difference = (float)portable_round_pc24((double)length_sq - 1.0);
  if (difference >= -FLT_EPSILON && difference <= FLT_EPSILON) {
    out->x = x;
    out->y = y;
  } else if (!(length_sq > FLT_MIN)) {
    out->x = out->y = 0;
  } else {
    double length = portable_round_pc24(sqrt((double)length_sq));
    double reciprocal = portable_round_pc24(1.0 / length);
    out->x = (float)portable_round_pc24(reciprocal * x);
    out->y = (float)portable_round_pc24(reciprocal * y);
  }
  return out;
}
// Presentation passes still called by recovered gameplay orchestration; guards
// are in gameplay_render_world.
#ifndef CRIMSON_GAME
extern "C" void terrain_render() {}
#endif
#ifndef CRIMSON_GAME
extern "C" void tutorial_timeline_update() { abort(); }
#endif
#ifndef CRIMSON_GAME
extern "C" void perk_prompt_update_and_render() {}
extern "C" void ui_render_aim_indicators() {}
extern "C" void hud_update_and_render() {}
extern "C" void ui_elements_update_and_render() {}
extern "C" void ui_cursor_render() {}
#endif
#ifndef CRIMSON_GAME
extern "C" void demo_trial_overlay_render(float *, float) { abort(); }
extern "C" void ui_render_keybind_help(float *, float) {}
#endif
static bool run_ended() {
  return game_state_pending == GAME_STATE_GAME_OVER ||
         game_state_pending == GAME_STATE_QUEST_FAILED ||
         game_state_pending == GAME_STATE_QUEST_RESULTS;
}
extern "C" uintptr_t portable_config() { return (uintptr_t)&cfg; }
extern "C" uintptr_t portable_input() { return (uintptr_t)&in; }
extern "C" float portable_aim_x() { return in.aim_x; }
extern "C" float portable_aim_y() { return in.aim_y; }
extern "C" float portable_move_x() { return in.move_x; }
extern "C" float portable_move_y() { return in.move_y; }
extern "C" bool portable_aim_turn_left() { return in.flags & 1u << 18; }
extern "C" bool portable_aim_turn_right() { return in.flags & 1u << 19; }
// What the ranked aim bound builds its camera from after a tick
// (src/crimson/replay/ranked.py): player one and the screen shake.
extern "C" float portable_player_x() { return player_state_table[0].position.x; }
extern "C" float portable_player_y() { return player_state_table[0].position.y; }
extern "C" float portable_player_health() { return player_state_table[0].health; }
extern "C" float portable_shake_x() { return camera_shake_offset_x; }
extern "C" float portable_shake_y() { return camera_shake_offset_y; }
// The timeline probe: each read compares the creature pool, player one's perk
// counts and the bonus pool with the previous read's.
static PortableProbe probe;
static float creature_health[385];
static bool creature_alive[385];
static int perk_seen[0x80];
static bool bonus_seen[0x10];
static int probe_mode;
static void probe_reset(int mode) {
  probe = PortableProbe{};
  probe_mode = mode;
  for (int i = 0; i < 385; ++i) {
    creature_alive[i] = creature_pool[i].active && creature_pool[i].health > 0;
    creature_health[i] = creature_pool[i].health;
  }
  memcpy(perk_seen, player_state_table[0].perk_counts, sizeof(perk_seen));
  for (int i = 0; i < 0x10; ++i)
    bonus_seen[i] = bonus_pool[i].picked;
}
extern "C" uintptr_t portable_probe() {
  player_state_t &p = player_state_table[0];
  for (int i = 0; i < 385; ++i) {
    creature_t &c = creature_pool[i];
    // A creature still in its slot loses health; one removed in the same tick
    // it was killed loses what it had left.
    if (creature_alive[i] && (!c.active || c.health < creature_health[i]))
      probe.damage += creature_health[i] - (c.active ? fmaxf(c.health, 0) : 0);
    creature_alive[i] = c.active && c.health > 0;
    creature_health[i] = c.health;
  }
  probe.picks = 0;
  for (int id = 0; id < 0x80; ++id) {
    for (int n = perk_seen[id]; n < p.perk_counts[id] && probe.picks < 8; ++n)
      probe.pick_ids[probe.picks++] = id;
    perk_seen[id] = p.perk_counts[id];
  }
  for (int i = 0; i < 0x10; ++i) {
    if (bonus_pool[i].picked && !bonus_seen[i] && bonus_pool[i].bonus_id == BONUS_ID_NUKE)
      ++probe.nukes;
    bonus_seen[i] = bonus_pool[i].picked;
  }
  probe.x = p.position.x;
  probe.y = p.position.y;
  probe.health = p.health;
  probe.elapsed_ms = probe_mode == GAME_MODE_QUEST ? quest_spawn_timeline : run_elapsed_ms;
  probe.experience = p.experience;
  probe.level = p.level;
  probe.weapon_id = p.weapon_id;
  probe.kills = creature_kill_count;
  const float timers[8] = {bonus_double_xp_timer, bonus_weapon_power_up_timer, p.fire_bullets_timer,
                           bonus_freeze_timer, bonus_reflex_boost_timer, bonus_energizer_timer,
                           p.shield_timer, p.speed_bonus_timer};
  memcpy(probe.timers, timers, sizeof(timers));
  return (uintptr_t)&probe;
}
extern "C" uintptr_t portable_commands() { return (uintptr_t)commands; }
extern "C" uintptr_t portable_output() { return (uintptr_t)output; }
static void trace_init(const char *stage) {
#ifndef __wasm__
  if (getenv("CRIMSON_CORE_TRACE_INIT"))
    fprintf(stderr, "init: %s\n", stage);
#else
  (void)stage;
#endif
}
extern "C" int portable_init(uint32_t seed, int mode, int major, int minor) {
#ifdef CRIMSON_GAME
  GameTick game_tick;
#endif
  trace_init("begin");
  ready = false;
  if (cfg.detail > 5 || cfg.unlock > 50 || cfg.unlock_full > 50 ||
      cfg.retry > 2147483647u || cfg.preserve_bugs > 1)
    return 0;
  portable_preserve_bugs = (unsigned char)cfg.preserve_bugs;
  for (auto n : cfg.weapon_usage)
    if (n > 2147483647u)
      return 0;
  if (mode != GAME_MODE_SURVIVAL && mode != GAME_MODE_RUSH &&
      mode != GAME_MODE_QUEST)
    return 0;
  if (mode == GAME_MODE_QUEST &&
      (major < 1 || major > 5 || minor < 1 || minor > 10))
    return 0;
  trace_init("reset data");
#ifdef CRIMSON_GAME
  game_reset_run_data();
#else
  portable_reset_data();
#endif
  string_used = 0;
  rng = seed;
  menu_requested = false;
  tick = 0;
  running_down = false;
  run_down_ms = 500;
  // A fresh game's values; nothing resets them between runs. Original bug 32:
  // slot 0 matches the chain id, so the fix starts with no chain.
  shock_chain_projectile_id = portable_preserve_bugs ? 0 : -1;
  perk_lean_mean_exp_tick_timer_s = 0;
  in = {0, 0, 512, 512, 0};
#ifdef CRIMSON_GAME
  game_init_run();
#else
  grim_interface_ptr = &headless_grim;
  friendly.value = cfg.friendly_fire ? 1 : 0;
  transparency.value = 0.8f;
  verbose.value = 0;
  pad_distance.value = 128;
  extern cvar_float_t *cv_bodiesFade;
  bodies_fade.value = 1;
  cv_bodiesFade = &bodies_fade;
  cv_friendlyFire = &friendly;
  cv_terrainBodiesTransparency = &transparency;
  cv_verbose = &verbose;
  extern cvar_float_t *cv_padAimDistMul;
  cv_padAimDistMul = &pad_distance;
#endif
  config_blob.player_count = 1;
  config_blob.game_mode = (game_mode_id_t)mode;
  config_blob.texture_scale = 1;
  config_blob.screen_width = 1024;
  config_blob.screen_height = 768;
  config_blob.detail_preset = cfg.detail;
  config_blob.hardcore = cfg.hardcore;
  config_blob.violence_disabled = cfg.violence;
  quest_fail_retry_count = cfg.retry;
  config_blob.music_volume = 1;
  config_blob.sfx_volume = 1;
  config_blob.key_reload = 101;
  config_blob.key_pick_perk = 102;
  config_blob.input_config[0].fire_key = 100;
  config_blob.input_config[0].axis_move_x = 0;
  config_blob.input_config[0].axis_move_y = 1;
  terrain_texture_width = 1024;
  terrain_texture_height = 1024;
  terrain_texture_failed = 0;
  quest_unlock_index = cfg.unlock;
  quest_unlock_index_hardcore = cfg.unlock_full;
  extern game_status_t game_status_blob;
  game_status_blob.quest_unlock_index = cfg.unlock;
  game_status_blob.quest_unlock_index_hardcore = cfg.unlock_full;
  memcpy(game_status_blob.weapon_usage_counts, cfg.weapon_usage,
         sizeof(cfg.weapon_usage));
  for (int i = 0; i < 50; ++i)
    new (&quest_meta_table[i]) quest_meta_cpp_t;
  for (int i = 0; i < 128; ++i)
    new (&perk_meta_table[i]) perk_meta_cpp_t;
  for (int i = 0; i < 15; ++i)
    new (&bonus_meta_table[i]) bonus_meta_cpp_t;
  trace_init("creature pool");
  creature_pool_global_init();
  trace_init("player table");
  player_state_table_global_init();
  trace_init("projectile pool");
  projectile_pool_global_init();
  trace_init("weapon defaults");
  weapon_table_defaults_global_init();
  trace_init("perk database");
  perks_init_database();
  trace_init("bonus metadata");
  bonus_metadata_init();
  trace_init("quest database");
  quest_database_init();
  game_state_id = GAME_STATE_GAMEPLAY;
  game_state_pending = GAME_STATE_PENDING_IDLE_SENTINEL;
  run_active = 1;
  trace_init("gameplay reset");
  gameplay_reset_state();
  player_input_t &keys = player_state_table[0].input;
  keys.fire_key = 100;
  keys.axis_move_x = 0;
  keys.axis_move_y = 1;
  // Codes the host's grim_is_key_active maps to the recorded key flags.
  keys.move_key_forward = 0x100;
  keys.move_key_backward = 0x101;
  keys.turn_key_left = 0x102;
  keys.turn_key_right = 0x103;
  keys.aim_key_left = 0x104;
  keys.aim_key_right = 0x105;
  quest_stage_major = major;
  quest_stage_minor = minor;
  trace_init("quest start");
  if (mode == GAME_MODE_QUEST)
    quest_start_selected(major, minor);
  // A successful, silent audio backend keeps the native music-selection RNG
  // gate open.
  extern music_fade_out_flags_t music_fade_out_flags;
  memset(music_fade_out_flags, 1, sizeof(music_fade_out_flags));
  music_ready = 1;
  // audio_init_music's load order: distinct ids keep the game-over and quest
  // music from posing as the random game-tune request (extra_0).
  int track = 0;
  music_track_intro_id = track++;
  music_track_shortie_monk_id = track++;
  music_playlist_entry_count = 6;
  for (int i = 0; i < music_playlist_entry_count; ++i)
    music_playlist[i] = track++;
  music_track_crimson_theme_id = track++;
  music_track_crimsonquest_id = track;
  music_track_game_playlist = track + 1;
  music_track_extra_1 = track + 2;
#ifdef CRIMSON_GAME
  game_run_ready();
#endif
  crt_rand();
  probe_reset(mode);
  ready = true;
  trace_init("ready");
  return 1;
}
// The menu request is consumed at the recovered mid-tick prompt. Picks run
// in order in the between-tick prelude, as they do in the current replay API.
extern "C" int portable_step_many(uint32_t count) {
#ifdef CRIMSON_GAME
  GameTick game_tick;
#endif
  if (!ready || count > 16 || run_down_ms < 0)
    return 0;
  // Replay input flags (src/crimson/replay/types.py): buttons and held keys,
  // then the movement scheme (bits 8-11) and aim scheme (bits 12-15), each with
  // a presence bit. Validation and defaults follow Python's decoder.
  constexpr uint32_t buttons = 1 | 2 | 4 | 1u << 16 | 1u << 17 | 1u << 18 | 1u << 19;
  constexpr uint32_t move_keys_present = 8, move_keys = 16 | 32 | 64 | 128;
  constexpr uint32_t move_present = 0x100, aim_present = 0x1000;
  uint32_t move_mode = in.flags >> 9 & 7, aim_scheme = in.flags >> 13 & 7;
  if (!isfinite(in.move_x) || !isfinite(in.move_y) || !isfinite(in.aim_x) ||
      !isfinite(in.aim_y) ||
      (in.flags & ~(buttons | move_keys_present | move_keys | move_present |
                    7u << 9 | aim_present | 7u << 13)) != 0 ||
      (!(in.flags & move_keys_present) && (in.flags & move_keys)) ||
      (!(in.flags & move_present) && move_mode != 0) || move_mode > 5 ||
      (!(in.flags & aim_present) && aim_scheme != 0) || aim_scheme == 6) {
    ready = false;
    return 0;
  }
  // Like Python, the schemes come with each tick's input. Recordings without
  // them ran static movement when they held movement keys, else the pad.
  config_blob.movement_schemes[0] =
      in.flags & move_present ? (int)move_mode
                              : in.flags & move_keys_present ? 2 : 3;
  // The 3-bit field stores the -1 scheme as all ones.
  config_blob.aim_schemes[0] = aim_scheme == 7 ? -1 : (int)aim_scheme;
  menu_requested = false;
  for (uint32_t i = 0; i < count; ++i) {
    int command = commands[i].type, argument = commands[i].argument;
    if ((command != 1 && command != 2) || config_game_mode == GAME_MODE_RUSH ||
        perk_pending_count <= 0 || player_state_table[0].health <= 0) {
      ready = false;
      return 0;
    }
    if (command == 2) {
      if (argument != 0) {
        ready = false;
        return 0;
      }
      menu_requested = true;
      continue;
    }
    int n = player_state_table[0].perk_counts[PERK_ID_PERK_MASTER] > 0   ? 7
            : player_state_table[0].perk_counts[PERK_ID_PERK_EXPERT] > 0 ? 6
                                                                         : 5;
    if (argument < 0 || argument >= n) {
      ready = false;
      return 0;
    }
    if (perk_choices_dirty) {
      perks_generate_choices();
      perk_choices_dirty = 0;
    }
    if (perk_choice_ids[argument] <= 0) {
      ready = false;
      return 0;
    }
    perk_apply(perk_choice_ids[argument]);
    --perk_pending_count;
    perk_choices_dirty = 1;
  }
  frame_dt = 1.0f / 60.0f;
  // game_frame_update: Reflex Boosted slows the frame while the world renders.
  if (run_active && perk_count_get(perk_id_reflex_boosted) != 0)
    frame_dt *= 0.9f;
  frame_dt_ms = (int)(frame_dt * 1000.0f);
  // Mouse-relative aim records the cursor itself; other schemes record world aim.
  bool cursor = config_blob.aim_schemes[0] == 3;
  ui_mouse_x = cursor ? in.aim_x : in.aim_x + camera_offset_x;
  ui_mouse_y = cursor ? in.aim_y : in.aim_y + camera_offset_y;
  gameplay_update_and_render();
  if (game_state_pending == GAME_STATE_PERK_SELECTION)
    game_state_pending = GAME_STATE_PENDING_IDLE_SENTINEL;
  // ui_elements_update_and_render: the timeline runs down by the restored
  // frame_dt_ms from the frame that ends the run.
  running_down = running_down || run_ended();
  if (running_down)
    run_down_ms -= frame_dt_ms;
  crt_rand();
  ++tick;
  return 1;
}
#ifdef CRIMSON_GAME
#include "session.inc"
#endif
extern "C" int portable_step(int command, int argument) {
  if (command == 0)
    return portable_step_many(0);
  commands[0] = {command, argument};
  return portable_step_many(1);
}
static void put(uint32_t x) {
  if (used >= 262144)
    abort();
  output[used++] = x;
}
static void put(int x) { put((uint32_t)x); }
static void put(unsigned char x) { put((uint32_t)x); }
static void put(float x) {
  uint32_t b;
  memcpy(&b, &x, 4);
  put(b);
}
static void put(bool x) { put((uint32_t)x); }
template <class T> static void put(T x) { put((uint32_t)x); }
static int portable_effect_index(const effect_entry_t *p) {
  if (!p)
    return 513;
  if (p == &effect_discard_entry)
    return 512;
  return int(p - effect_pool);
}
static int portable_creature_index(const creature_t *p) {
  return p ? int(p - creature_pool) : 385;
}
// Test-only math seam; it calls the same routines used by recovered gameplay.
extern "C" int portable_math_probe(uint32_t operation, uint32_t a, uint32_t b) {
  used = 0;
  if (operation == 1 || operation == 3) {
    vec2f_t source, target;
    memcpy(&source.x, &a, 4);
    memcpy(&source.y, &b, 4);
    vec2f_t *out = operation == 3 ? &source : &target;
    if (D3DXVec2Normalize(out, &source) != out)
      return 0;
    put(out->x);
    put(out->y);
  } else if (operation == 2 && a >= 1 && a <= 2000) {
    float power = portable_crt_pow_pc24((float)a, 1.8f);
    put(power);
    put(1000 - (int)(power * -1000.0f));
  } else if (operation == 4) {
    float angle, speed;
    memcpy(&angle, &a, 4);
    memcpy(&speed, &b, 4);
    put(portable_mul32(portable_cos(angle), speed));
    put(portable_mul32(portable_sin(angle), speed));
  } else {
    return 0;
  }
  return used;
}
// Test-only builder oracle. It leaves the run unsteppable until reinitialized.
extern "C" int portable_builder_probe(uint32_t seed, uint32_t index,
                                      uint32_t hardcore, uint32_t players) {
#ifdef CRIMSON_GAME
  GameTick game_tick;
#endif
  if (index >= 50 || hardcore > 1 || players < 1 || players > 4)
    return 0;
  cfg = {};
  cfg.detail = 5;
  cfg.hardcore = hardcore;
  if (!portable_init(seed, GAME_MODE_QUEST, index / 10 + 1, index % 10 + 1))
    return 0;
  ready = false;
  config_blob.player_count = players;
  rng = seed;
  memset(quest_spawn_table, 0, sizeof(quest_spawn_entry_t) * 256);
  quest_spawn_count = 0;
  reinterpret_cast<quest_builder_fn_t>(quest_meta_table[index].builder)(
      quest_spawn_table, &quest_spawn_count);
  if (quest_spawn_count < 0 || quest_spawn_count > 256)
    return 0;
  used = 0;
  put(quest_spawn_count);
  put(rng);
  for (int i = 0; i < quest_spawn_count; ++i) {
    const auto &s = quest_spawn_table[i];
    put(s.pos_x);
    put(s.pos_y);
    put(s.heading);
    put(s.template_id);
    put(s.trigger_time_ms);
    put(s.count);
  }
  return used;
}
extern "C" int portable_snapshot() {
  used = 0;
#include "snapshot.inc"
  return used;
}
#ifndef __wasm__
#include <vector>
struct BufferedTick {
  PortableInput input;
  uint32_t count;
  PortableCommand commands[16];
};
int main(int argc, char **argv) {
  if (argc == 2 && strcmp(argv[1], "--math-probe") == 0) {
    uint32_t args[3];
    size_t bytes;
    while ((bytes = fread(args, 1, sizeof(args), stdin))) {
      if (bytes != sizeof(args))
        return 4;
      int n = portable_math_probe(args[0], args[1], args[2]);
      if (!n)
        return 3;
      fwrite(&n, 4, 1, stdout);
      fwrite(output, 4, n, stdout);
    }
    return ferror(stdin) ? 6 : 0;
  }
  if (argc == 2 && strcmp(argv[1], "--quest-probe") == 0) {
    uint32_t args[4];
    while (fread(args, sizeof(args), 1, stdin) == 1) {
      int n = portable_builder_probe(args[0], args[1], args[2], args[3]);
      if (!n)
        return 3;
      fwrite(&n, 4, 1, stdout);
      fwrite(output, 4, n, stdout);
    }
    return ferror(stdin) ? 6 : 0;
  }
  bool reset_check = argc == 2 && strcmp(argv[1], "--reset-check") == 0;
  // `--fields <file>` emits only the listed snapshot indices (little-endian
  // u32 each) per snapshot, so whole-run comparisons stay small.
  std::vector<uint32_t> fields;
  if (argc == 3 && strcmp(argv[1], "--fields") == 0) {
    FILE *f = fopen(argv[2], "rb");
    if (!f)
      return 8;
    uint32_t index;
    while (fread(&index, 4, 1, f) == 1)
      fields.push_back(index);
    fclose(f);
  }
  std::vector<uint32_t> selected;
  auto emit = [&](int n) {
    if (fields.empty()) {
      fwrite(&n, 4, 1, stdout);
      fwrite(output, 4, n, stdout);
      return;
    }
    selected.clear();
    for (uint32_t index : fields) {
      if (index >= (uint32_t)n)
        abort();
      selected.push_back(output[index]);
    }
    uint32_t count = (uint32_t)selected.size();
    fwrite(&count, 4, 1, stdout);
    fwrite(selected.data(), 4, count, stdout);
  };
  std::vector<BufferedTick> saved;
  if (fread(&cfg, sizeof(cfg), 1, stdin) != 1)
    return 2;
  if (!portable_init(cfg.seed, cfg.mode, cfg.major, cfg.minor))
    return 3;
  int n = portable_snapshot();
  emit(n);
  while (true) {
    size_t bytes = fread(&in, 1, sizeof(in), stdin);
    if (!bytes)
      break;
    if (bytes != sizeof(in))
      return 4;
    uint32_t count;
    if (fread(&count, 4, 1, stdin) != 1 || count > 16 ||
        fread(commands, sizeof(PortableCommand), count, stdin) != count)
      return 4;
    if (!portable_step_many(count)) {
      fprintf(stderr, "reject tick %u xp %d pending %d health %g\n", tick,
              player_state_table[0].experience, perk_pending_count,
              player_state_table[0].health);
      return 5;
    }
    if (reset_check) {
      BufferedTick t;
      t.input = in;
      t.count = count;
      memcpy(t.commands, commands, count * sizeof(PortableCommand));
      saved.push_back(t);
    }
    n = portable_snapshot();
    emit(n);
  }
  if (reset_check) {
    std::vector<uint32_t> final(output, output + n);
    PortableConfig a = cfg;
    cfg.detail = 0;
    cfg.unlock = 0;
    cfg.unlock_full = 0;
    memset(cfg.weapon_usage, 0, sizeof(cfg.weapon_usage));
    if (!portable_init(0x12345678, GAME_MODE_RUSH, 1, 1))
      return 7;
    for (int i = 0; i < 200; ++i) {
      in = {1, 0, 512, 512, 0x1700}; // mouse aim
      if (!portable_step(0, 0))
        return 7;
    }
    cfg = a;
    if (!portable_init(cfg.seed, cfg.mode, cfg.major, cfg.minor))
      return 7;
    for (const auto &t : saved) {
      in = t.input;
      memcpy(commands, t.commands, t.count * sizeof(PortableCommand));
      if (!portable_step_many(t.count))
        return 7;
    }
    if (portable_snapshot() != n || memcmp(final.data(), output, n * 4) != 0)
      return 7;
    fprintf(stderr, "native A/B/A passed\n");
  }
  return ferror(stdin) ? 6 : 0;
}
#endif
