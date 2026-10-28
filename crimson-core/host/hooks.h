#pragma once
// Included ahead of every recovered source (build.py): what the edits to them
// (adapter.py) call.
#include "api.h"
#include "crt_rand.h"
#include "portable_math.h"
#include "rules.h"
// The custom quest a run plays in place of a stock one, or null (host/host.cpp, seams/custom-quest.patch).
extern "C" struct quest_meta_t *portable_custom_quest;
#ifdef CRIMSON_GAME
#include "../game/render_passes.h"
extern "C" {
// The game module takes the recording only inside a tick (host/game.inc).
extern unsigned char game_ticking;
// Cooldowns use ticks during gameplay and frames in menus (game/audio_timing.cpp).
void game_audio_cooldowns(float dt);
// A run the client plays (host/session.inc).
bool game_live_run();
// Between a live run's ticks the world only draws (game/changes/world-draw.patch).
bool game_live_between_ticks();
// A scripted run's cursor, until its script moves it (game/frame.cpp).
bool game_cursor_hidden();
bool game_live_pause();
void game_live_pick(int choice);
// The buttons that start a run, while a co-op session is on (host/coop_live.inc):
// true when it takes the click.
bool game_coop_setup_run(int mode, int major, int minor);
bool game_coop_next_run(int choice);
// An end screen shows its buttons, past its name entry.
void game_coop_end_ready();
// Presentation metadata shared by live custom quests and their replays (host/watch.inc).
char *game_custom_quest_author();
// The Ranked row (host/ranked.inc). Its table reader returns a FILE, which some
// recovered files define themselves, so highscore_load_table declares it.
extern bool ranked_checked;
void ranked_layout(void);
void ranked_menu(float *base, float *tips, bool list_open);
// A pinned row's card and its replay (host/watch.inc).
int highscore_watch_row(int hovered, int rows, int *selected);
void highscore_watch(float *card, struct highscore_record_t *record);
// The build's name (host/game.inc).
char *game_version_label();
// RTX (game/rtx.cpp): the rendering mode, 0 classic, 1 RTX, its console
// commands, the world's bounds in the frame and the analytic beams that replace
// the stamped streaks (game/rtx/rtx.patch).
extern int rtx_render_mode;
void console_cmd_render_mode(void);
void console_cmd_toggle_rtx(void);
void rtx_world(int begin);
void rtx_material(int pass); // a HOST_PASS_* of game/render_passes.h
void rtx_bonus(int emblem, float grid_x, float grid_y, float center_x, float center_y);
void rtx_ground(int kind); // a HOST_GROUND_* of game/render_passes.h
void rtx_ground_decal(int effect_id, float red);
void rtx_ice(int effect_id); // an effect's material among the effects (effects_render), -1 after the last
// RTX fluid smoke (game/rtx_smoke.cpp): the smoke the run's ticks make, and the
// field drawn after the world's sprites, in place of native puffs while active.
extern int rtx_smoke_on;
bool rtx_smoke_active();
void rtx_smoke_reset();
// What RTX keeps beside a run (game/rtx.cpp), cleared as every run starts: Typ-o-Shooter, the tutorial and the
// demo start theirs outside the host's sessions.
void rtx_reset();
void rtx_smoke_spawned(int index);
void rtx_smoke_flush();
void rtx_smoke_puff(const struct effect_entry_t *entry);
void rtx_smoke_soot(int index);
void rtx_smoke_muzzle(float heading);
void rtx_smoke_rocket(float flow_x, float flow_y, float vx, float vy);
void rtx_smoke_nuke();
void rtx_smoke_flame();
void rtx_smoke_source_end();
void rtx_smoke_blast(float x, float y, float scale);
void rtx_smoke_wake(int type, float sx, float sy, float ex, float ey, float dt);
void rtx_smoke_impulse(float sx, float sy, float ex, float ey, float radius, float strength, float curl, int kind,
                       float duration, float expansion_speed);
void rtx_smoke_tick(float dt);
void rtx_reset();
// RTX explosion lights and ion contact glows (game/rtx_lights.cpp), and Monster Vision's heat (game/rtx_heat.cpp),
// which replaces its aura while RTX draws (rtx_drawing).
void rtx_explosion_begin(float x, float y, float scale);
void rtx_explosion_end();
void rtx_explosion_rocket(int slot);
void rtx_secondary_spawn(int slot);
void rtx_explosion_effect(int effect_id, const struct effect_entry_t *entry);
void rtx_explosions_age(float dt);
void rtx_explosion_release(const struct effect_entry_t *entry);
int rtx_explosion_owns(const struct effect_entry_t *entry);
void rtx_explosions_draw();
bool rtx_drawing();
bool rtx_effect_quad(const float *points);
bool rtx_effect_vertices(const void *vertices, int count);
bool rtx_effect_sprite(const struct effect_entry_t *entry, unsigned color);
void rtx_glint(bool active);
void rtx_pressure_ring(float x, float y, float radius, float alpha);
void rtx_effect_flush();
void rtx_plasma(int slot, float alpha);
void rtx_ion_arc(float sx, float sy, float ex, float ey, float scale, float alpha);
void rtx_pulse(float cx, float cy, float size, float angle, float r, float g, float b, float a);
// The arc loop's creature search, at most two arcs a cell per shot (game/ion_arcs.cpp).
int ion_arc_find(float *pos, float radius, int start_index);
void rtx_contact_glows(float alpha);
void rtx_heat_trails(float alpha);
void rtx_heat(int type_id, float transition_alpha);
void rtx_smoke(float alpha);
void console_cmd_rtx_smoke(void);
void console_cmd_rtx_debug(void);
void console_cmd_render_size(void);
void rtx_beam_body(float origin_x, float origin_y, float head_x, float head_y, float start, float span, float step,
                   float effect_scale, float alpha, float r, float g, float b);
void rtx_beam_head(float center_x, float center_y, float rotation, float effect_scale, bool fire);
// A smoke source for the scope it opens in (a gun's fire, a rocket's sprite).
struct RtxSmokeMuzzle {
  explicit RtxSmokeMuzzle(float heading) { rtx_smoke_muzzle(heading); }
  ~RtxSmokeMuzzle() { rtx_smoke_source_end(); }
};
struct RtxSmokeRocket {
  RtxSmokeRocket(float flow_x, float flow_y, float vx, float vy) { rtx_smoke_rocket(flow_x, flow_y, vx, vy); }
  ~RtxSmokeRocket() { rtx_smoke_source_end(); }
};
struct RtxExplosion {
  RtxExplosion(float x, float y, float scale) { rtx_explosion_begin(x, y, scale); }
  ~RtxExplosion() { rtx_explosion_end(); }
};
struct RtxRocketExplosion {
  explicit RtxRocketExplosion(int slot) { rtx_explosion_rocket(slot); }
  ~RtxRocketExplosion() { rtx_explosion_rocket(-1); }
};
struct RtxSmokeNuke {
  RtxSmokeNuke() { rtx_smoke_nuke(); }
  ~RtxSmokeNuke() { rtx_smoke_source_end(); }
};
struct RtxSmokeFlame {
  RtxSmokeFlame() { rtx_smoke_flame(); }
  ~RtxSmokeFlame() { rtx_smoke_source_end(); }
};
// A track's volume a tick sets, on the original's track for the one it names
// (host/coop.inc).
void game_music_volume(int id, float volume);
}
// The repack's stored entry for a path (game/repack.cpp).
char *grim_lookup_blob_entry(char *path);
#define PORTABLE_RECORDED game_ticking
// Grim's own switch: set, it draws nothing (a replay's undrawn ticks, host/watch.inc).
extern unsigned char grim_render_disabled;
#define PORTABLE_DRAWING (!grim_render_disabled)
#else
// The verifier always takes the recording, and draws nothing (host/grim.inc).
#define PORTABLE_RECORDED 1
#define PORTABLE_DRAWING 0
#endif
