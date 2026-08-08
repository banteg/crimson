#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>

#include "crimsonland_highscore.h"

extern char default_player_name[];
extern SYSTEMTIME local_system_time;
extern unsigned char config_show_online_scores;
extern unsigned char config_highscore_date_mode;
extern unsigned char config_highscore_duplicate_mode;
extern unsigned char config_hardcore;
extern int config_selected_saved_name_slot;

int crt_rand(void);
char *highscore_build_path(void);
char *highscore_read_record(char *buffer, FILE *fp);
highscore_record_t *highscore_find_name_entry(
    const char *player_name,
    int count);
int highscore_compare_survival_score_desc(const void *left, const void *right);
int highscore_compare_rush_field32_desc(const void *left, const void *right);
int highscore_compare_quest_field32_asc_nonzero_first(
    const void *left,
    const void *right);

static __inline void highscore_record_reset_light(highscore_record_t *record)
{
    memset(record, 0, sizeof(*record));
    strcpy(record->player_name, default_player_name);
    record->flags = 0;
    record->sentinel_pipe = '|';
    record->sentinel_ff = 0xff;
    record->random_tag = crt_rand() & 0x0fee050f;
}

void highscore_load_table(void)
{
    highscore_record_t stored;
    char *path;
    FILE *fp;
    int count;
    int current_date_checksum;
    int index;

    highscore_record_reset_light(&stored);

    path = highscore_build_path();
    highscore_table_count = 0;
    for (index = 0; index < 100; index++) {
        highscore_record_reset_light(&highscore_table[index]);
    }

    count = 0;
    fp = fopen(path, "rb");
    if (fp == 0) {
        return;
    }

    current_date_checksum = highscore_date_checksum(
        local_system_time.wYear,
        local_system_time.wMonth,
        local_system_time.wDay);

    while (!feof(fp)) {
        highscore_record_t *replace;
        game_mode_id_t mode;

        if (highscore_read_record((char *)&stored, fp) == 0) {
            continue;
        }

        mode = config_game_mode;
        if ((int)stored.game_mode_id != (int)mode) {
            continue;
        }
        if (mode == GAME_MODE_QUEST) {
            if (config_hardcore != 0) {
                if (stored.hardcore_marker != 0x75) {
                    continue;
                }
            } else if (stored.hardcore_marker != 0) {
                continue;
            }
        }

        if (!config_show_online_scores &&
            (stored.flags & 1) != 0 &&
            (stored.flags & 2) == 0) {
            continue;
        }

        if (config_highscore_date_mode == 3) {
            if (local_system_time.wDay != stored.day ||
                local_system_time.wYear - 2000 != stored.year_offset ||
                local_system_time.wMonth != stored.month) {
                continue;
            }
        } else if (config_highscore_date_mode == 2) {
            if (current_date_checksum != stored.date_checksum ||
                local_system_time.wYear != stored.year_offset + 2000) {
                continue;
            }
        } else if (config_highscore_date_mode == 1) {
            if (local_system_time.wMonth != stored.month ||
                local_system_time.wYear - 2000 != stored.year_offset) {
                continue;
            }
        }

        if (config_highscore_duplicate_mode == 1) {
            replace = highscore_find_name_entry(stored.player_name, count);
            if (replace != 0) {
                *replace = stored;
                continue;
            }
            mode = config_game_mode;
        }

        if (count == 99) {
            replace = &highscore_table[0];
            if (mode == GAME_MODE_RUSH) {
                for (index = 1; index < 100; index++) {
                    if ((int)highscore_table[index].survival_elapsed_ms <
                        (int)replace->survival_elapsed_ms) {
                        replace = &highscore_table[index];
                    }
                }
                *replace = stored;
                continue;
            }
            if (mode == GAME_MODE_QUEST) {
                for (index = 1; index < 100; index++) {
                    if ((int)highscore_table[index].survival_elapsed_ms >
                        (int)replace->survival_elapsed_ms) {
                        replace = &highscore_table[index];
                    }
                }
                *replace = stored;
                continue;
            }
            for (index = 1; index < 100; index++) {
                if ((int)highscore_table[index].score_xp <
                    (int)replace->score_xp) {
                    replace = &highscore_table[index];
                }
            }
            *replace = stored;
            continue;
        }

        highscore_table[count] = stored;
        count++;
        highscore_table_count = count;
    }

    fclose(fp);
    if (highscore_table_count > 100) {
        highscore_table_count = 100;
    }

    if (config_game_mode == GAME_MODE_RUSH) {
        qsort(
            highscore_table,
            100,
            sizeof(highscore_record_t),
            highscore_compare_rush_field32_desc);
    } else if (config_game_mode == GAME_MODE_QUEST) {
        qsort(
            highscore_table,
            100,
            sizeof(highscore_record_t),
            highscore_compare_quest_field32_asc_nonzero_first);
    } else {
        qsort(
            highscore_table,
            100,
            sizeof(highscore_record_t),
            highscore_compare_survival_score_desc);
    }

    if (config_selected_saved_name_slot == 0) {
        for (index = 0; index < highscore_table_count; index++) {
            int inner;
            int best;

            best = index;
            if ((highscore_table[index].flags & 4) != 0 ||
                (highscore_table[index].flags & 1) == 0) {
                continue;
            }

            for (inner = 0; inner < highscore_table_count; inner++) {
                if ((highscore_table[inner].flags & 1) == 0 ||
                    strcmp(
                        highscore_table[index].player_name,
                        highscore_table[inner].player_name) != 0) {
                    continue;
                }

                if (highscore_table[best].game_mode_id == GAME_MODE_RUSH) {
                    if ((int)highscore_table[best].survival_elapsed_ms <
                        (int)highscore_table[inner].survival_elapsed_ms) {
                        best = inner;
                    }
                } else if ((int)highscore_table[best].score_xp <
                           (int)highscore_table[inner].score_xp) {
                    best = inner;
                }
            }
            highscore_table[best].flags |= 4;
        }
        return;
    }

    for (index = 0; index < highscore_table_count; index++) {
        if ((highscore_table[index].flags & 1) != 0) {
            highscore_table[index].flags |= 4;
        }
    }
}
