#include <stdio.h>

extern "C" {
extern int config_player_count;
extern int config_game_mode;
extern char freeware_text_buffer[];
}

extern "C" char *highscore_build_path()
{
    if (config_player_count == 1) {
        if (config_game_mode == 2) {
            sprintf(freeware_text_buffer, "rush.top");
            return freeware_text_buffer;
        }
        if (config_game_mode == 1) {
            sprintf(freeware_text_buffer, "career.top");
            return freeware_text_buffer;
        }
        if (config_game_mode == 3) {
            sprintf(freeware_text_buffer, "levels.top");
            return freeware_text_buffer;
        }
    } else {
        if (config_game_mode == 2) {
            sprintf(freeware_text_buffer, "rush2.top");
            return freeware_text_buffer;
        }
        if (config_game_mode == 1) {
            sprintf(freeware_text_buffer, "career2.top");
            return freeware_text_buffer;
        }
        if (config_game_mode == 3) {
            sprintf(freeware_text_buffer, "levels2.top");
            return freeware_text_buffer;
        }
    }
    sprintf(freeware_text_buffer, "general.top");
    return freeware_text_buffer;
}
