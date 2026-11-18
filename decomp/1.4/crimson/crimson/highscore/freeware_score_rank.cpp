#include "freeware_score.h"

extern "C" int config_game_mode;

extern "C" int freeware_score_rank(int score)
{
    int i;
    if (config_game_mode == 2) {
        for (i = 0; i < 100; ++i)
            freeware_score_table[i].value = freeware_score_table[i].seconds;
    }

    freeware_sort_score_table();

    for (i = 0; i < 100; ++i) {
        if (freeware_score_table[i].value < score)
            return i;
    }
    return -1;
}
