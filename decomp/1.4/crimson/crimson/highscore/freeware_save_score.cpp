#include "crimsonland_types.h"
#include "freeware_score.h"
#include <stdio.h>

extern "C" {
extern game_mode_id_t config_game_mode;
extern freeware_score_entry freeware_last_score;
extern float freeware_elapsed_seconds;
extern int current_player_index;
extern freeware_player_t player_state_table[2];
}

extern "C" unsigned char freeware_save_score()
{
    FILE *file;
    if (config_game_mode == 2)
        file = fopen("rush.top", "ab");
    else
        file = fopen("career.top", "ab");
    if (!file)
        return 0;

    fseek(file, 0, SEEK_END);
    freeware_last_score.value = config_game_mode == 2
        ? (int)freeware_elapsed_seconds
        : player_state_table[current_player_index].experience;
    fwrite(&freeware_last_score, sizeof(freeware_last_score), 1, file);
    fclose(file);
    return 1;
}
