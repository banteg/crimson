#ifndef CRIMSONLAND_HIGHSCORE_H
#define CRIMSONLAND_HIGHSCORE_H

typedef struct IDirectSoundBuffer *LPDIRECTSOUNDBUFFER;

#include "cl_build.h"
#include "crimsonland_console.h"
#include "crimsonland_types.h"

// 1.9.9 moved the score tables to a new directory.
#if CL_BUILD < 10909
#define HIGHSCORE_DIR "scores4"
#else
#define HIGHSCORE_DIR "scores5"
#endif

extern highscore_record_t highscore_active_record;
extern highscore_record_t highscore_table[100];
extern int highscore_table_count;
extern game_mode_id_t config_game_mode;
extern int run_elapsed_ms;
extern int highscore_score_xp;
extern char highscore_date_label_buffer[];

#ifdef __cplusplus
extern "C" {
#endif

unsigned char highscore_record_is_valid(highscore_record_t *record);
int highscore_iso_week(int year, int month, int day);
char *highscore_format_date_label(int day, int month_index, int year);
unsigned char highscore_submit_full_version_guard(highscore_record_t *record);
#if CL_BUILD == 10908
/* 1.9.8's packer returns nothing: eax ends holding src->random_tag. */
typedef void highscore_pack_result_t;
#else
typedef highscore_record_t *highscore_pack_result_t;
#endif
highscore_pack_result_t highscore_record_pack_for_submit(
    highscore_record_t *src,
    highscore_record_t *dst);
char highscore_record_equals(
    highscore_record_t *left,
    highscore_record_t *right);
void highscore_save_record(highscore_record_t *record);
void highscore_save_active(void);
int highscore_rank_index(void);
int crt_sprintf(char *dst, const char *format, ...);

#ifdef __cplusplus
}
#endif

#endif
