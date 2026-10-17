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
extern "C" {
// The game module takes the recording only inside a tick (host/game.inc).
extern unsigned char game_ticking;
// Cooldowns use ticks during gameplay and frames in menus (game/audio_timing.cpp).
void game_audio_cooldowns(float dt);
// A run the client plays (host/session.inc).
bool game_live_run();
// Between a live run's ticks the world only draws (game/changes/world-draw.patch).
bool game_live_between_ticks();
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
