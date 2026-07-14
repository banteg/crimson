#include <direct.h>
#include <stdio.h>
#include <string.h>

#include "crimsonland_highscore.h"

extern char highscore_named_path_buf[128];
extern char highscore_path_buf[128];
extern char highscore_cwd_buf[512];
extern char highscore_cwd_buf_tail_nul;
extern unsigned char highscore_cwd_cached;
extern int config_player_count;
extern int config_selected_saved_name_slot;
extern char config_saved_name_0[][27];
extern unsigned char config_hardcore;
extern int quest_stage_major;
extern int quest_stage_minor;
extern cvar_float_t *cv_verbose;

char *highscore_build_path(void)
{
    int selected_name;
    int suffix_index;

    if (!highscore_cwd_cached) {
        _getcwd(highscore_cwd_buf, 511);
        highscore_cwd_buf_tail_nul = 0;
        highscore_cwd_cached = 1;
    }

    if (config_game_mode == GAME_MODE_RUSH) {
        sprintf(
            highscore_path_buf,
            "%s\\scores5\\rush.hi",
            highscore_cwd_buf);
    } else if (config_game_mode == GAME_MODE_SURVIVAL) {
        sprintf(
            highscore_path_buf,
            "%s\\scores5\\survival.hi",
            highscore_cwd_buf);
    } else if (config_game_mode == GAME_MODE_QUEST) {
        if (config_hardcore != 0) {
            sprintf(
                highscore_path_buf,
                "%s\\scores5\\quest%d_%d.hi",
                highscore_cwd_buf,
                quest_stage_major,
                quest_stage_minor);
        } else {
            sprintf(
                highscore_path_buf,
                "%s\\scores5\\questhc%d_%d.hi",
                highscore_cwd_buf,
                quest_stage_major,
                quest_stage_minor);
        }
    } else {
        sprintf(
            highscore_path_buf,
            "scores5\\unknown.hi",
            config_saved_name_0[config_selected_saved_name_slot]);
    }

    if (config_player_count == 2) {
        suffix_index = strlen(highscore_path_buf) - 3;
        highscore_path_buf[suffix_index++] = '_';
        highscore_path_buf[suffix_index++] = '2';
        highscore_path_buf[suffix_index++] = '.';
        highscore_path_buf[suffix_index++] = 'h';
        highscore_path_buf[suffix_index] = 'i';
        highscore_path_buf[suffix_index + 1] = 0;
    }

    selected_name = config_selected_saved_name_slot;
    if (selected_name != 0) {
        sprintf(
            highscore_named_path_buf,
            "%s%s",
            highscore_path_buf,
            config_saved_name_0[selected_name]);
        console_printf(
            &console_log_queue,
            "Opening named cache '%s'\n",
            highscore_named_path_buf);
        return highscore_named_path_buf;
    }

    if (cv_verbose->value != 0.0f) {
        console_printf(
            &console_log_queue,
            "Opening '%s'\n",
            highscore_path_buf);
    }
    return highscore_path_buf;
}
