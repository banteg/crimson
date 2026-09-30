#include "api.h"
#include "crimsonland_gameplay.h"
#include "crimsonland_metadata.h"
#include "grim2d_cpp.h"
#include <math.h>
#include <new>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static PortableInput in;
static PortableConfig cfg;
static PortableCommand commands[16];
static bool ready;
static bool menu_requested;
static char string_arena[65536];
static size_t string_used;
static uint32_t rng;
static uint32_t tick;
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
extern unsigned char music_playlist_randomized_latch, sfx_unmuted_flag;
extern int music_playlist_entry_count, music_track_extra_0;
extern music_playlist_t music_playlist;
extern unsigned char survival_reward_fire_seen, survival_reward_handout_enabled;
extern int survival_reward_weapon_guard_id, survival_recent_death_count,
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
static cvar_float_t friendly, transparency, verbose, pad_distance, bodies_fade;
// Device output does not consume gameplay RNG. Music selection keeps the
// recovered implementation.
extern "C" int crt_rand() {
  rng = rng * 214013u + 2531011u;
  return (rng >> 16) & 0x7fff;
}
extern "C" void crt_free(void *) {}
extern "C" char *strdup_malloc(char *s) {
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
extern "C" char *wrap_text_to_width_alloc(char *s, int) {
  return strdup_malloc(s);
}
extern "C" int crt_sprintf(char *dst, const char *fmt, ...) {
  va_list v;
  va_start(v, fmt);
  int n = vsprintf(dst, fmt, v);
  va_end(v);
  return n;
}
extern "C" void console_printf(console_queue_t *, char *, ...) {}
extern "C" int console_input_poll() { return 0; }
extern "C" int play_time_get() { return 0; }
extern "C" unsigned char game_is_full_version() { return 1; }
extern "C" void game_save_status() {}
extern "C" void game_state_set(game_state_id_t s) { game_state_pending = s; }
extern "C" void demo_mode_start() { abort(); }
extern "C" void sfx_play(int, float) {}
extern "C" int sfx_play_panned(int, const vec2f_t *, float) { return 0; }
extern "C" int sfx_entry_start_playback(music_entry_t *) { return 1; }
extern "C" void sfx_entry_set_volume(music_entry_t *, float) {}
extern "C" bool input_primary_just_pressed() { return (in.flags & 2) != 0; }
extern "C" vec2f_t *__stdcall D3DXVec2Normalize(vec2f_t *out,
                                                const vec2f_t *src) {
  float length = sqrtf(src->x * src->x + src->y * src->y);
  float x = src->x, y = src->y;
  out->x = length ? x / length : 0;
  out->y = length ? y / length : 0;
  return out;
}
// Presentation passes still called by recovered gameplay orchestration; guards
// are in gameplay_render_world.
extern "C" void terrain_render() {}
extern "C" void tutorial_timeline_update() { abort(); }
extern "C" void perk_prompt_update_and_render() {}
extern "C" void ui_render_aim_indicators() {}
extern "C" void hud_update_and_render() {}
extern "C" void ui_elements_update_and_render() {}
extern "C" void ui_cursor_render() {}
extern "C" void demo_trial_overlay_render(float *, float) { abort(); }
extern "C" void ui_render_keybind_help(float *, float) {}
extern "C" uintptr_t portable_config() { return (uintptr_t)&cfg; }
extern "C" uintptr_t portable_input() { return (uintptr_t)&in; }
extern "C" uintptr_t portable_commands() { return (uintptr_t)commands; }
extern "C" uintptr_t portable_output() { return (uintptr_t)output; }
extern "C" int portable_init(uint32_t seed, int mode, int major, int minor) {
  ready = false;
  if (cfg.detail > 5 || cfg.unlock > 50 || cfg.unlock_full > 50 ||
      cfg.retry > 2147483647u)
    return 0;
  for (auto n : cfg.weapon_usage)
    if (n > 2147483647u)
      return 0;
  if (mode != GAME_MODE_SURVIVAL && mode != GAME_MODE_RUSH &&
      mode != GAME_MODE_QUEST)
    return 0;
  if (mode == GAME_MODE_QUEST &&
      (major < 1 || major > 5 || minor < 1 || minor > 10))
    return 0;
  portable_reset_data();
  string_used = 0;
  rng = seed;
  menu_requested = false;
  tick = 0;
  in = {0, 0, 512, 512, 0};
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
  config_blob.movement_schemes[0] = 3;
  config_blob.aim_schemes[0] = 0;
  config_blob.key_reload = 101;
  config_blob.key_pick_perk = 102;
  config_blob.input_config[0].fire_key = 100;
  config_blob.input_config[0].axis_move_x = 0;
  config_blob.input_config[0].axis_move_y = 1;
  terrain_texture_width = 1024;
  terrain_texture_height = 1024;
  terrain_texture_failed = 0;
  quest_unlock_index = cfg.unlock;
  quest_unlock_index_full = cfg.unlock_full;
  extern game_status_t game_status_blob;
  game_status_blob.quest_unlock_index = cfg.unlock;
  game_status_blob.quest_unlock_index_full = cfg.unlock_full;
  memcpy(game_status_blob.weapon_usage_counts, cfg.weapon_usage,
         sizeof(cfg.weapon_usage));
  for (int i = 0; i < 50; ++i)
    new (&quest_selected_meta[i]) quest_meta_cpp_t;
  for (int i = 0; i < 128; ++i)
    new (&perk_meta_table[i]) perk_meta_cpp_t;
  for (int i = 0; i < 15; ++i)
    new (&bonus_meta_table[i]) bonus_meta_cpp_t;
  creature_pool_global_init();
  player_state_table_global_init();
  projectile_pool_global_init();
  weapon_table_defaults_global_init();
  perks_init_database();
  bonus_metadata_init();
  quest_database_init();
  game_state_id = GAME_STATE_GAMEPLAY;
  game_state_pending = GAME_STATE_PENDING_IDLE_SENTINEL;
  render_pass_mode = 1;
  gameplay_reset_state();
  player_state_table[0].input.fire_key = 100;
  player_state_table[0].input.axis_move_x = 0;
  player_state_table[0].input.axis_move_y = 1;
  quest_stage_major = major;
  quest_stage_minor = minor;
  if (mode == GAME_MODE_QUEST)
    quest_start_selected(major, minor);
  // A successful, silent audio backend keeps the native music-selection RNG
  // gate open.
  extern sfx_mute_flags_t sfx_mute_flags;
  memset(sfx_mute_flags, 1, sizeof(sfx_mute_flags));
  sfx_unmuted_flag = 1;
  music_playlist_entry_count = 6;
  music_track_extra_0 = 0;
  for (int i = 0; i < 6; ++i)
    music_playlist[i] = i + 1;
  crt_rand();
  ready = true;
  return 1;
}
// The menu request is consumed at the recovered mid-tick prompt. Picks run
// in order in the between-tick prelude, as they do in the current replay API.
extern "C" int portable_step_many(uint32_t count) {
  if (!ready || count > 16 || game_state_pending == GAME_STATE_GAME_OVER ||
      game_state_pending == GAME_STATE_QUEST_FAILED ||
      game_state_pending == GAME_STATE_QUEST_RESULTS)
    return 0;
  constexpr uint32_t controls =
      38656; // dual-action movement (3), world/mouse aim (4).
  constexpr uint32_t buttons = 1 | 2 | 4 | 65536 | 131072;
  if (!isfinite(in.move_x) || !isfinite(in.move_y) || !isfinite(in.aim_x) ||
      !isfinite(in.aim_y) || (in.flags & ~buttons) != controls) {
    ready = false;
    return 0;
  }
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
  frame_dt_ms = (int)(frame_dt * 1000.0f);
  ui_mouse_x = in.aim_x + camera_offset_x;
  ui_mouse_y = in.aim_y + camera_offset_y;
  gameplay_update_and_render();
  if (game_state_pending == GAME_STATE_PERK_SELECTION)
    game_state_pending = GAME_STATE_PENDING_IDLE_SENTINEL;
  crt_rand();
  ++tick;
  return 1;
}
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
// Test-only builder oracle. It leaves the run unsteppable until reinitialized.
extern "C" int portable_builder_probe(uint32_t seed, uint32_t index,
                                      uint32_t hardcore, uint32_t players) {
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
  reinterpret_cast<quest_builder_fn_t>(quest_selected_meta[index].builder)(
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
  std::vector<BufferedTick> saved;
  if (fread(&cfg, sizeof(cfg), 1, stdin) != 1)
    return 2;
  if (!portable_init(cfg.seed, cfg.mode, cfg.major, cfg.minor))
    return 3;
  int n = portable_snapshot();
  fwrite(&n, 4, 1, stdout);
  fwrite(output, 4, n, stdout);
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
    fwrite(&n, 4, 1, stdout);
    fwrite(output, 4, n, stdout);
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
      in = {1, 0, 512, 512, 38656};
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
