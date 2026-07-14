#include "crimsonland_highscore.h"

int highscore_rank_index(void)
{
    int i;

    if (config_game_mode == GAME_MODE_RUSH) {
        for (i = 0; i < highscore_table_count; i++) {
            if (survival_elapsed_ms >
                (int)highscore_table[i].survival_elapsed_ms) {
                return i;
            }
        }
        return highscore_table_count;
    }

    if (config_game_mode == GAME_MODE_QUEST) {
        for (i = 0; i < highscore_table_count; i++) {
            if (survival_elapsed_ms <
                (int)highscore_table[i].survival_elapsed_ms) {
                return i;
            }
        }
        return highscore_table_count;
    }

    for (i = 0; i < highscore_table_count; i++) {
        if (highscore_score_xp > (int)highscore_table[i].score_xp) {
            return i;
        }
    }
    return highscore_table_count;
}
