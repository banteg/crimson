#ifndef CRIMSONLAND_HIGHSCORE_H
#define CRIMSONLAND_HIGHSCORE_H

typedef struct IDirectSoundBuffer *LPDIRECTSOUNDBUFFER;

#include "crimsonland_console.h"
#include "crimsonland_types.h"

extern highscore_record_t highscore_active_record;
extern highscore_record_t highscore_table[];
extern int highscore_table_count;
extern game_mode_id_t config_game_mode;
extern int survival_elapsed_ms;
extern int highscore_score_xp;

#ifdef __cplusplus
extern "C" {
#endif

unsigned char highscore_record_is_valid(highscore_record_t *record);
unsigned char highscore_submit_full_version_guard(highscore_record_t *record);
highscore_record_t *highscore_record_pack_for_submit(
    highscore_record_t *src,
    highscore_record_t *dst);
void highscore_save_record(highscore_record_t *record);
void highscore_save_active(void);
int highscore_rank_index(void);

#ifdef __cplusplus
}
#endif

#endif
