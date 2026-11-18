#include "crimsonland_types.h"
#include "freeware_score.h"
#include <stdio.h>
extern "C" {
extern game_mode_id_t config_game_mode;
extern freeware_score_entry freeware_last_score;
extern float freeware_elapsed_seconds;
extern int current_player_index;
#if CL_BUILD == 10400
extern player_state_t player_state_table[2];
extern unsigned char freeware_cheated;
#else
extern freeware_player_t player_state_table[2];
#endif
#if CL_BUILD > 10002
extern float freeware_fps_min, freeware_fps_max, freeware_fps[50];
void freeware_score_key_init();
unsigned char freeware_score_decode(char *bytes, int size);
void freeware_score_encode(char *bytes, int size);
char *highscore_build_path();
void crt_free(void *);
#endif
}

extern "C" unsigned char freeware_save_score()
{
#if CL_BUILD == 10002
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
#else
#if CL_BUILD == 10400
    if (freeware_cheated)
        return 1;
#endif
    freeware_score_key_init();
    float average = 0;
    for (int i = 0; i < 50; ++i)
        average += freeware_fps[i];
    average *= .02f;
    if (average < 15)
        return 0;

    FILE *file = fopen(highscore_build_path(), "rb");
    char *bytes;
    int size = 0;
    if (!file) {
        bytes = new char[sizeof(freeware_score_entry) + 4];
    } else {
        fseek(file, 0, SEEK_END);
        size = ftell(file) - 4;
        bytes = new char[size + sizeof(freeware_score_entry) + 4];
        fseek(file, 0, SEEK_SET);
        fread(bytes, size + 4, 1, file);
        fclose(file);
        if (!freeware_score_decode(bytes, size)) {
            crt_free(bytes);
            return 0;
        }
    }
    freeware_last_score.seconds = (int)freeware_elapsed_seconds;
#if CL_BUILD == 10400
    freeware_last_score.value = player_state_table[current_player_index].freeware.experience;
    freeware_last_score.version = 1.4f;
#else
    freeware_last_score.value = player_state_table[current_player_index].experience;
    freeware_last_score.version = 1.3f;
#endif
    freeware_last_score.average_fps = average;
    freeware_last_score.max_fps = freeware_fps_max;
    freeware_last_score.min_fps = freeware_fps_min;
    *(freeware_score_entry *)(bytes + size) = freeware_last_score;
    freeware_score_encode(bytes, size + sizeof(freeware_score_entry));

    file = fopen(highscore_build_path(), "wb");
    fseek(file, 0, SEEK_SET);
    fwrite(bytes, size + sizeof(freeware_score_entry) + 4, 1, file);
    fclose(file);
    crt_free(bytes);
    return 1;
#endif
}
