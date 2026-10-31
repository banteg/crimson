#include "api.h"
#include "crt_rand.h"
#include "rules.h"
#include "crimsonland_gameplay.h"
#include "crimsonland_metadata.h"
#include "grim2d_cpp.h"
#include "portable_math.h"
#include <float.h>
#include <math.h>
#include <iterator>
#include <new>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
// Each player's input for the tick, player one first.
static PortableInput in[2];
// The codes the host's Grim (grim.inc) maps to each player's input: the fire
// key, the first of the two move axes, and the first of the six move and aim keys.
static constexpr struct {
  int fire, axis, keys;
} PLAYER_KEYS[2] = {{100, 0, 0x100}, {200, 2, 0x110}};
static PortableConfig cfg;
static PortableQuest quest;
static quest_meta_t custom_quest_meta;
static char custom_quest_title[65] = "Custom quest";
static char custom_quest_author[32] = "";
static bool custom_quest_valid_for(const PortableQuest &q);
// The weapons a custom quest can start with: none of the unused ids.
static bool custom_quest_weapon_valid(int id) { return id >= 1 && id <= 53 && (id < 34 || id > 40) && (id < 46 || id > 49); }
static void custom_quest_build(quest_spawn_entry_t *entries, int *count);
extern "C" quest_meta_t *portable_custom_quest;
quest_meta_t *portable_custom_quest;
extern "C" unsigned char portable_preserve_bugs;
unsigned char portable_preserve_bugs;
unsigned int portable_rules, portable_legacy_coop_reload, portable_cl_build;
// The perks the run's build numbers, as perks_init_database sets them: 1.9.8's end at 53, before Man Bomb.
extern "C" int perk_id_max, perk_id_count;
void portable_perk_range() {
  perk_id_max = portable_rules_1_9_8 ? 53 : 57;
  perk_id_count = perk_id_max + 1;
}
// The run's profile, from its config: its bug policy, rules and build, with the perk range the build sets. A run whose
// start runs no portable_init (a keyframe's, or in the client one the original sets up itself, host/session.inc)
// keeps no other run's.
static void portable_profile_set(const PortableConfig &config) {
  portable_preserve_bugs = (unsigned char)config.preserve_bugs;
  portable_rules = config.rules;
  portable_legacy_coop_reload = config.legacy_coop_reload;
  portable_cl_build = config.cl_build;
  portable_perk_range();
}
PortablePlayerRules portable_player_rules[2];
// Each weapon's shot sound as its audio_asset_id_table slot, which the sound globals name (rules.h), for 1.9.8's Fire
// Bullets reroll. The original compares loaded ids, which tell the sounds apart only with every one loaded: the
// verifier loads none, and the original without sound or assets gives them all one id. weapon_table_init over
// distinct ids gives the slots instead, whatever ids the run holds. No build or run changes them: portable_init fills
// them, and inside the original game_start too, for the runs the original sets up itself.
extern "C" int audio_asset_id_table[83];
extern "C" void weapon_table_init(void);
int portable_weapon_shot_slot[64];
int portable_sound_slot(const int *sound) { return (int)(sound - audio_asset_id_table); }
static void weapon_shot_slots() {
  int loaded[std::size(audio_asset_id_table)];
  memcpy(loaded, audio_asset_id_table, sizeof loaded);
  for (int &id : audio_asset_id_table)
    id = portable_sound_slot(&id);
  weapon_table_init();
  for (size_t i = 0; i < std::size(portable_weapon_shot_slot); ++i)
    portable_weapon_shot_slot[i] = weapon_table[i].shot_sfx_base_id;
  memcpy(audio_asset_id_table, loaded, sizeof loaded);
}
float portable_impact_heading(float x, float y) {
  return (float)(portable_atan2(y, x) - 1.5707964f);
}
static PortableCommand commands[16];
static bool ready;
static bool menu_requested;
// The perk menu opened in the last tick. The perk screen pauses the game, so
// the next tick may start with one pick, and closes the menu either way.
static bool perk_menu_open;
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
// The input of the player the tick is updating: player_update runs once per
// player with current_player_index naming it, and its queries read that player's.
static const PortableInput &player_in() {
  if (current_player_index < 0 || current_player_index >= (int)cfg.players)
    abort();
  return in[current_player_index];
}
#include "grim.inc"
extern "C" {
extern IGrim2D_cpp *grim_interface_ptr;
extern int current_player_index;
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
void perks_rebuild_available();
void gameplay_reset_state();
void gameplay_update_and_render();
void quest_start_selected(int, int);
void perks_generate_choices();
void perk_apply(int);
}
// A fresh game's state, which nothing resets between runs, on the run's profile (portable_profile_set), for every
// run: those portable_init sets up, and in the client those the original sets up itself (host/session.inc), as
// Python's initialize_run starts every mode. The players' added run state starts with a fresh game's intervals, as
// Python's PlayerState does, and Lean Mean Exp Machine's tick with none. Original bug 32: the Shock Chain id a fresh
// game starts with, 0, matches projectile slot 0, so the fix starts with no chain.
static void portable_fresh_game() {
  for (auto &player : portable_player_rules)
    player = {1.4f, 1.4f, 0};
  perk_lean_mean_exp_tick_timer_s = 0;
  shock_chain_projectile_id = portable_preserve_bugs ? 0 : -1;
}
#ifdef CRIMSON_GAME
#include "game.inc"
// What RTX keeps beside a run (game/rtx.cpp), which a new or restored run clears.
extern "C" void rtx_reset();
// An RTX debug view picked since the world last drew (game/rtx.cpp), which a paused replay draws again.
extern "C" bool rtx_debug_redraw();
#endif
static cvar_float_t friendly, transparency, verbose, pad_distance, bodies_fade;
// Device output does not consume gameplay RNG; a tick's music call draws its
// tune (music_play_exclusive).
extern "C" uint32_t *crt_rand_stream() {
#ifdef CRIMSON_GAME
  // In a session, gameplay RNG belongs to run start and ticks; presentation must
  // not draw it. Between a live run's ticks, the original's frame and menus draw
  // a stream of their own (the tick draws the frame's value, portable_step_many).
  if (game_session && !game_ticking) {
    if (!game_live)
      abort();
    static uint32_t presentation = 1;
    return &presentation;
  }
#endif
  return &rng;
}
extern "C" int crt_rand() { return crt_rand_step(crt_rand_stream()); }
#ifdef CRIMSON_GAME
extern "C" void music_play_exclusive_recovered(int sfx_id);
static void game_music_play(int sfx_id, int draw);
static bool watch_holds_tune(int sfx_id);
#endif
// A tick's music call (the first hit's in-game tune, the end tunes), split in
// two. The simulation half is the original's playlist latch and the tune's random
// draw, whatever the audio: a hit draws the tune once, until another tune clears
// the latch (Python's game_tune_started). The game module's playback half plays
// the track, or the in-game tune the draw picks (-1 for none), by the player's
// own audio settings and leaves the latch alone. Outside a tick, a link waiting
// to play holds the original's tunes (host/watch.inc).
extern "C" void music_play_exclusive(int sfx_id) {
#ifdef CRIMSON_GAME
  if (!game_ticking) {
    if (!watch_holds_tune(sfx_id))
      music_play_exclusive_recovered(sfx_id);
    return;
  }
#endif
  int draw = -1;
  if (sfx_id == music_track_game_playlist) {
    if (music_playlist_randomized_latch)
      return;
    draw = crt_rand();
    music_playlist_randomized_latch = 1;
  } else {
    music_playlist_randomized_latch = 0;
  }
#ifdef CRIMSON_GAME
  game_music_play(sfx_id, draw);
#endif
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
#if defined(__wasm__) && !defined(CRIMSON_GAME)
// core.wasm imports nothing. wasi-libc's stdio locks through futex waits (WASI clock_time_get) and libc++abi's
// pure-virtual handler prints to stderr (fd_write), on paths this single-threaded module never takes.
extern "C" void __cxa_pure_virtual() { __builtin_trap(); }
extern "C" int __lockfile(FILE *) { return 0; }
extern "C" void __unlockfile(FILE *) {}
#endif
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
extern "C" bool input_primary_just_pressed() { return (player_in().flags & 2) != 0; }
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
extern "C" uintptr_t portable_quest() { return (uintptr_t)&quest; }
// The custom quest's builder: its table and drop/offer restrictions, where a stock builder would construct one.
static void custom_quest_build(quest_spawn_entry_t *entries, int *count) {
  for (int i = 2; i <= 14; ++i)
    if (quest.disable_bonuses & (1u << i))
      bonus_meta_table[i].enabled = 0;
  for (int i = 1; i <= 57; ++i)
    if (quest.disable_perks[i >> 5] & (1u << (i & 31)))
      perk_meta_table[i].available = 0;
  for (int i = 2; i <= 33; ++i)
    if (quest.disable_weapons[i >> 5] & (1u << (i & 31)))
      weapon_table[i].unlocked = 0;
  for (uint32_t i = 0; i < quest.count; ++i) {
    const PortableSpawn &s = quest.entries[i];
    entries[i].pos_x = s.x;
    entries[i].pos_y = s.y;
    entries[i].heading = s.heading;
    entries[i].template_id = s.template_id;
    entries[i].trigger_time_ms = s.trigger_ms;
    entries[i].count = s.count;
  }
  *count = (int)quest.count;
}
// The table src/crimson/quests/custom.py's validate_custom_quest accepts: positions a full arena beyond each edge,
// copies bounded per entry, per trigger time and in total, and restriction bitmasks within the droppable/offerable IDs.
static bool custom_quest_valid_for(const PortableQuest &q) {
  if (!custom_quest_weapon_valid((int)q.weapon_id) || q.count < 1 || q.count > 256)
    return false;
  if ((q.disable_bonuses & ~0x7ffcu) || (q.disable_perks[0] & ((1u << 0) | (1u << 7))) ||
      (q.disable_perks[1] & ~0x03ffffffu) || (q.disable_weapons[0] & 3u) || (q.disable_weapons[1] & ~3u))
    return false;
  for (uint32_t slot : q.terrain)
    if (slot > 7)
      return false;
  int copies[256], total = 0;
  for (uint32_t i = 0; i < q.count; ++i) {
    const PortableSpawn &s = q.entries[i];
    if (!(s.x >= -1024 && s.x <= 2048 && s.y >= -1024 && s.y <= 2048) || !isfinite(s.heading) ||
        s.template_id < 0 || s.template_id > 0x43 || s.template_id == 0x02 ||
        s.template_id == 0x37 || s.trigger_ms < 0 ||
        s.trigger_ms > 3600000 || s.count < 1 || s.count > 384)
      return false;
    copies[i] = s.count;
    total += copies[i];
  }
  for (uint32_t i = 0; i < q.count; ++i) {
    int at_trigger = 0;
    for (uint32_t j = 0; j < q.count; ++j)
      if (q.entries[j].trigger_ms == q.entries[i].trigger_ms)
        at_trigger += copies[j];
    if (at_trigger > 384)
      return false;
  }
  return total <= 8192;
}
static bool custom_quest_valid() { return custom_quest_valid_for(quest); }
extern "C" uintptr_t portable_input() { return (uintptr_t)in; }
extern "C" float portable_aim_x() { return player_in().aim_x; }
extern "C" float portable_aim_y() { return player_in().aim_y; }
extern "C" float portable_move_x() { return player_in().move_x; }
extern "C" float portable_move_y() { return player_in().move_y; }
extern "C" bool portable_aim_turn_left() { return player_in().flags & 1u << 18; }
extern "C" bool portable_aim_turn_right() { return player_in().flags & 1u << 19; }
// Each player's cursor for the tick (player_update's player_aim_screen_x): the
// recorded cursor under mouse-relative aim, else the world aim through the camera
// the tick starts with. The original's players share one mouse; recorded, each
// has its own.
static float aim_screen[2][2];
extern "C" float portable_aim_screen_x() { return aim_screen[&player_in() - in][0]; }
extern "C" float portable_aim_screen_y() { return aim_screen[&player_in() - in][1]; }
// Whether any player lives: perk commands need one (Python's all_players_dead).
static bool any_player_alive() {
  for (uint32_t i = 0; i < cfg.players; ++i)
    if (player_state_table[i].health > 0)
      return true;
  return false;
}
// What the ranked aim bound and input signals read after a tick
// (src/crimson/replay/ranked.py, service/src/verify.ts): a player's position and health, 0 for player one.
extern "C" float portable_player_x(uint32_t player) { return player_state_table[player].position.x; }
extern "C" float portable_player_y(uint32_t player) { return player_state_table[player].position.y; }
extern "C" float portable_player_health(uint32_t player) { return player_state_table[player].health; }
extern "C" float portable_nearest_creature(float x, float y) {
  float best = INFINITY;
  for (int i = 0; i < 385; ++i) {
    const creature_t &c = creature_pool[i];
    if (c.active && c.health > 0)
      best = fminf(best, sqrtf((c.position.x - x) * (c.position.x - x) + (c.position.y - y) * (c.position.y - y)));
  }
  return best;
}
// The timeline probe: each read compares the creature pool, player one's perk
// counts and the bonus pool with the previous read's, and reads each player.
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
  probe.elapsed_ms = probe_mode == GAME_MODE_QUEST ? quest_spawn_timeline : run_elapsed_ms;
  probe.experience = p.experience;
  probe.level = p.level;
  probe.kills = creature_kill_count;
  const float timers[5] = {bonus_double_xp_timer, bonus_weapon_power_up_timer, bonus_freeze_timer,
                           bonus_reflex_boost_timer, bonus_energizer_timer};
  memcpy(probe.timers, timers, sizeof(timers));
  for (uint32_t i = 0; i < cfg.players; ++i) {
    const player_state_t &player = player_state_table[i];
    probe.players[i] = {player.position.x, player.position.y, player.health, player.weapon_id,
                        player.fire_bullets_timer, player.shield_timer, player.speed_bonus_timer};
  }
  return (uintptr_t)&probe;
}
#ifndef CRIMSON_GAME
// The verifier draws nothing, so it hands out what each tick bakes into the
// terrain instead, as the original's fx_queue_render (wrapped, build.py) finds
// its queues; the game module bakes them itself (host/keyframes.inc).
static PortableBakes bakes;
extern "C" creature_type_table_t creature_type_table;
extern "C" void fx_queue_render_recovered();
extern "C" void fx_queue_render() {
  for (int i = 0; i < fx_queue_count; ++i) {
    const fx_queue_entry_t &e = fx_queue[i];
    int size_code = effect_id_table[e.effect_id].size_code;
    bakes.decal[i] = {e.pos_x, e.pos_y, e.width, e.height, e.rotation, e.color.r, e.color.g, e.color.b, e.color.a,
                      0x100 / size_code, effect_id_table[e.effect_id].frame};
  }
  for (int i = 0; i < fx_queue_rotated; ++i) {
    const effect_color_t &c = fx_rotated_color_r[i];
    bakes.corpse[i] = {fx_rotated_pos_x[i].x, fx_rotated_pos_x[i].y, fx_rotated_scale[i], fx_rotated_scale[i],
                       fx_rotated_rotation[i], c.r, c.g, c.b, c.a,
                       4, creature_type_table[fx_rotated_creature_type_id[i]].corpse_frame};
  }
  bakes.decals = fx_queue_count;
  bakes.corpses = fx_queue_rotated;
  fx_queue_render_recovered();
}
extern "C" uintptr_t portable_bakes() { return (uintptr_t)&bakes; }
#endif
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
      cfg.retry > 2147483647u || cfg.preserve_bugs > 1 || cfg.players < 1 || cfg.players > 2 || (cfg.rules != 1 && cfg.rules != 2) || cfg.legacy_coop_reload > 1 || (cfg.rules != 1 && cfg.legacy_coop_reload))
    return 0;
  // 1.9.8's rules arrived with rules 2 and have no rules-1 profile.
  if (cfg.cl_build != PORTABLE_CL_BUILD_1_9_93 && (cfg.cl_build != PORTABLE_CL_BUILD_1_9_8 || cfg.rules < 2))
    return 0;
  portable_profile_set(cfg);
  for (auto n : cfg.weapon_usage)
    if (n > 2147483647u)
      return 0;
  if (mode != GAME_MODE_SURVIVAL && mode != GAME_MODE_RUSH &&
      mode != GAME_MODE_QUEST)
    return 0;
  // A quest at stage 0.0 is the custom quest written at portable_quest.
  bool custom = mode == GAME_MODE_QUEST && major == 0 && minor == 0;
  if (mode == GAME_MODE_QUEST && !custom &&
      (major < 1 || major > 5 || minor < 1 || minor > 10))
    return 0;
  if (custom && (cfg.hardcore != 0 || !custom_quest_valid()))
    return 0;
  trace_init("reset data");
#ifdef CRIMSON_GAME
  game_reset_run_data();
  rtx_reset();
#else
  portable_reset_data();
#endif
  portable_fresh_game();
  string_used = 0;
  rng = seed;
  menu_requested = false;
  perk_menu_open = false;
  tick = 0;
  running_down = false;
  run_down_ms = 500;
  in[0] = in[1] = {0, 0, 512, 512, 0};
#ifdef CRIMSON_GAME
  game_init_run();
#else
  grim_interface_ptr = &headless_grim;
  friendly.value = cfg.friendly_fire ? 1 : 0;
  transparency.value = 0;
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
  config_blob.player_count = (int)cfg.players;
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
  for (int p = 0; p < (int)cfg.players; ++p) {
    config_blob.input_config[p].fire_key = PLAYER_KEYS[p].fire;
    config_blob.input_config[p].axis_move_x = PLAYER_KEYS[p].axis;
    config_blob.input_config[p].axis_move_y = PLAYER_KEYS[p].axis + 1;
  }
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
  trace_init("weapon shot sounds");
  weapon_shot_slots();
  trace_init("gameplay reset");
  gameplay_reset_state();
  // Codes the host's grim_is_key_active maps to each player's recorded key flags.
  for (int p = 0; p < (int)cfg.players; ++p) {
    player_input_t &keys = player_state_table[p].input;
    keys.fire_key = PLAYER_KEYS[p].fire;
    keys.axis_move_x = PLAYER_KEYS[p].axis;
    keys.axis_move_y = PLAYER_KEYS[p].axis + 1;
    keys.move_key_forward = PLAYER_KEYS[p].keys;
    keys.move_key_backward = PLAYER_KEYS[p].keys + 1;
    keys.turn_key_left = PLAYER_KEYS[p].keys + 2;
    keys.turn_key_right = PLAYER_KEYS[p].keys + 3;
    keys.aim_key_left = PLAYER_KEYS[p].keys + 4;
    keys.aim_key_right = PLAYER_KEYS[p].keys + 5;
  }
  quest_stage_major = major;
  quest_stage_minor = minor;
  // Stage 0.0 matches no level's rules, as Python's custom run has no stock level.
  custom_quest_meta = quest_meta_t{};
  custom_quest_meta.name = custom_quest_title;
  custom_quest_meta.terrain_id = (int)quest.terrain[0];
  custom_quest_meta.terrain_id_b = (int)quest.terrain[1];
  custom_quest_meta.terrain_id_c = (int)quest.terrain[2];
  custom_quest_meta.builder = custom_quest_build;
  custom_quest_meta.start_weapon_id = (int)quest.weapon_id;
  portable_custom_quest = custom ? &custom_quest_meta : nullptr;
  trace_init("quest start");
  if (mode == GAME_MODE_QUEST)
    quest_start_selected(major, minor);
  // A successful, silent audio backend, which the game module's music playback
  // reads.
  extern music_fade_out_flags_t music_fade_out_flags;
  memset(music_fade_out_flags, 1, sizeof(music_fade_out_flags));
  music_ready = 1;
  // audio_init_music's load order: distinct ids keep the game-over and quest
  // music from posing as the random game-tune request (extra_0). A run inside
  // the original ticks with these too (GameMusic, host/game.inc).
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
// Why portable_step_many refused its last tick, empty after one it took. The
// command rules read as Python's IllegalCommandError
// (src/crimson/sim/sessions.py).
static const char *refusal = "";
extern "C" uintptr_t portable_refusal() { return (uintptr_t)refusal; }
// A refused tick leaves earlier picks applied, so the run takes no more ticks.
static int refuse(const char *reason) {
  ready = false;
  refusal = reason;
  return 0;
}
// Replay input flags (src/crimson/replay/types.py): buttons and held keys, then
// the movement scheme (bits 8-11) and aim scheme (bits 12-15), each with a
// presence bit.
constexpr uint32_t INPUT_BUTTONS = 1 | 2 | 4 | 1u << 16 | 1u << 17 | 1u << 18 | 1u << 19;
constexpr uint32_t INPUT_MOVE_KEYS_PRESENT = 8, INPUT_MOVE_KEYS = 16 | 32 | 64 | 128;
constexpr uint32_t INPUT_MOVE_PRESENT = 0x100, INPUT_AIM_PRESENT = 0x1000;
// Whether an input is one Python's decoder accepts: each player's in a tick, and each record a co-op peer sends.
static bool portable_input_valid(const PortableInput &input) {
  uint32_t move_mode = input.flags >> 9 & 7, aim_scheme = input.flags >> 13 & 7;
  return isfinite(input.move_x) && isfinite(input.move_y) && isfinite(input.aim_x) && isfinite(input.aim_y) &&
         (input.flags & ~(INPUT_BUTTONS | INPUT_MOVE_KEYS_PRESENT | INPUT_MOVE_KEYS | INPUT_MOVE_PRESENT | 7u << 9 |
                          INPUT_AIM_PRESENT | 7u << 13)) == 0 &&
         ((input.flags & INPUT_MOVE_KEYS_PRESENT) || !(input.flags & INPUT_MOVE_KEYS)) &&
         ((input.flags & INPUT_MOVE_PRESENT) || move_mode == 0) && move_mode <= 5 &&
         ((input.flags & INPUT_AIM_PRESENT) || aim_scheme == 0) && aim_scheme != 6;
}
// The menu request is consumed at the recovered mid-tick prompt. Picks run
// in order in the between-tick prelude, as they do in the current replay API.
extern "C" int portable_step_many(uint32_t count) {
#ifdef CRIMSON_GAME
  GameTick game_tick;
#endif
  refusal = !ready            ? "no run in progress"
            : count > 16      ? "more than 16 commands"
            : run_down_ms < 0 ? "a tick past the run's end"
                              : "";
  if (*refusal)
    return 0;
  for (uint32_t p = 0; p < cfg.players; ++p) {
    const PortableInput &input = in[p];
    if (!portable_input_valid(input))
      return refuse("malformed input");
    // Like Python, the schemes come with each tick's input. Recordings without
    // them ran static movement when they held movement keys, else the pad.
    uint32_t move_mode = input.flags >> 9 & 7, aim_scheme = input.flags >> 13 & 7;
    config_blob.movement_schemes[p] = input.flags & INPUT_MOVE_PRESENT        ? (int)move_mode
                                      : input.flags & INPUT_MOVE_KEYS_PRESENT ? 2
                                                                              : 3;
    // The 3-bit field stores the -1 scheme as all ones.
    config_blob.aim_schemes[p] = aim_scheme == 7 ? -1 : (int)aim_scheme;
  }
  menu_requested = false;
#ifndef CRIMSON_GAME
  bakes.decals = bakes.corpses = 0;
#endif
  bool menu_open = perk_menu_open;
  perk_menu_open = false;
  for (uint32_t i = 0; i < count; ++i) {
    int command = commands[i].type, argument = commands[i].argument;
    if (command != 1 && command != 2)
      return refuse("unknown command");
    bool pick = command == 1;
    if (config_game_mode == GAME_MODE_RUSH)
      return refuse("perk command in Rush");
    if (pick && !menu_open)
      return refuse("perk_pick without an open perk menu");
    if (perk_pending_count <= 0)
      return refuse(pick ? "perk_pick without a pending perk"
                         : "perk_menu_open without a pending perk");
    if (!any_player_alive())
      return refuse(pick ? "perk_pick while every player is dead"
                         : "perk_menu_open while every player is dead");
    if (!pick) {
      if (argument != 0)
        return refuse("perk_menu_open with an argument");
      menu_requested = true;
      continue;
    }
    menu_open = false;
    int n = player_state_table[0].perk_counts[PERK_ID_PERK_MASTER] > 0   ? 7
            : player_state_table[0].perk_counts[PERK_ID_PERK_EXPERT] > 0 ? 6
                                                                         : 5;
    if (argument < 0 || argument >= n)
      return refuse("perk_pick of a choice that is not offered");
    if (perk_choices_dirty) {
      perks_generate_choices();
      perk_choices_dirty = 0;
    }
    if (perk_choice_ids[argument] <= 0)
      return refuse("perk_pick of a choice that is not offered");
    perk_apply(perk_choice_ids[argument]);
    --perk_pending_count;
    perk_choices_dirty = 1;
  }
  frame_dt = 1.0f / 60.0f;
  // game_frame_update: Reflex Boosted slows the frame while the world renders.
  if (run_active && perk_count_get(perk_id_reflex_boosted) != 0)
    frame_dt *= 0.9f;
#ifdef CRIMSON_GAME
  // Keep the pre-gameplay delta, as game_frame_update's frame_dt_copy does:
  // gameplay can temporarily scale frame_dt for the Reflex Boost bonus.
  const float audio_dt = frame_dt;
#endif
  frame_dt_ms = (int)(frame_dt * 1000.0f);
  // Mouse-relative aim records the cursor itself; other schemes record world aim.
  for (uint32_t p = 0; p < cfg.players; ++p) {
    bool cursor = config_blob.aim_schemes[p] == 3;
    aim_screen[p][0] = cursor ? in[p].aim_x : in[p].aim_x + camera_offset_x;
    aim_screen[p][1] = cursor ? in[p].aim_y : in[p].aim_y + camera_offset_y;
  }
  // The shared cursor, as the original's single mouse leaves it, is player one's.
  ui_mouse_x = aim_screen[0][0];
  ui_mouse_y = aim_screen[0][1];
  gameplay_update_and_render();
#ifdef CRIMSON_GAME
  game_audio_tick(audio_dt);
#endif
  if (game_state_pending == GAME_STATE_PERK_SELECTION) {
    perk_menu_open = true;
    game_state_pending = GAME_STATE_PENDING_IDLE_SENTINEL;
  }
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
  cfg.rules = CRIMSON_REPLAY_RULES;
  cfg.cl_build = PORTABLE_CL_BUILD_1_9_93;
  cfg.detail = 5;
  cfg.hardcore = hardcore;
  cfg.players = 1;
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
  PortableInput input[2];
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
  // A custom quest's stream carries its table after the config.
  if (cfg.mode == GAME_MODE_QUEST && cfg.major == 0 && cfg.minor == 0 && fread(&quest, sizeof(quest), 1, stdin) != 1)
    return 2;
  if (!portable_init(cfg.seed, cfg.mode, cfg.major, cfg.minor))
    return 3;
  int n = portable_snapshot();
  emit(n);
  // Each tick: one input per player, then its commands.
  const size_t inputs = cfg.players * sizeof(PortableInput);
  while (true) {
    size_t bytes = fread(in, 1, inputs, stdin);
    if (!bytes)
      break;
    if (bytes != inputs)
      return 4;
    uint32_t count;
    if (fread(&count, 4, 1, stdin) != 1 || count > 16 ||
        fread(commands, sizeof(PortableCommand), count, stdin) != count)
      return 4;
    if (!portable_step_many(count)) {
      fprintf(stderr, "reject tick %u: %s (xp %d pending %d health %g)\n", tick,
              refusal, player_state_table[0].experience, perk_pending_count,
              player_state_table[0].health);
      return 5;
    }
    if (reset_check) {
      BufferedTick t;
      memcpy(t.input, in, sizeof in);
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
    // B plays the other build, whose rules leave nothing behind for A either.
    cfg.cl_build = a.cl_build == PORTABLE_CL_BUILD_1_9_8 ? PORTABLE_CL_BUILD_1_9_93 : PORTABLE_CL_BUILD_1_9_8;
    cfg.rules = 2;
    cfg.legacy_coop_reload = 0;
    cfg.detail = 0;
    cfg.players = 1;
    cfg.unlock = 0;
    cfg.unlock_full = 0;
    memset(cfg.weapon_usage, 0, sizeof(cfg.weapon_usage));
    if (!portable_init(0x12345678, GAME_MODE_RUSH, 1, 1))
      return 7;
    for (int i = 0; i < 200; ++i) {
      in[0] = {1, 0, 512, 512, 0x1700}; // mouse aim
      if (!portable_step(0, 0))
        return 7;
    }
    cfg = a;
    if (!portable_init(cfg.seed, cfg.mode, cfg.major, cfg.minor))
      return 7;
    for (const auto &t : saved) {
      memcpy(in, t.input, sizeof in);
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
