#pragma once
// Included ahead of every recovered source (build.py): what the edits to them
// (adapter.py) call.
#include "api.h"
#include "crt_rand.h"
#include "portable_math.h"
#include "rules.h"
#ifdef CRIMSON_GAME
extern "C" {
// The game module takes the recording only inside a tick (host/game.inc).
extern unsigned char game_ticking;
// A run the client plays (host/session.inc).
bool game_live_run();
bool game_live_pause();
void game_live_pick(int choice);
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
}
// The repack's stored entry for a path (game/repack.cpp).
char *grim_lookup_blob_entry(char *path);
#define PORTABLE_RECORDED game_ticking
#else
// The verifier always takes the recording.
#define PORTABLE_RECORDED 1
#endif
