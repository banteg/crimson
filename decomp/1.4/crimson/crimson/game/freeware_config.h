#ifndef FREEWARE_CONFIG_H
#define FREEWARE_CONFIG_H

#include "cl_build.h"

// freeware_save_config writes this entire record to disk in a single fwrite.
struct freeware_config_t {
#if CL_BUILD >= 10400
    bool audio_disabled, safe_mode;
#endif
    unsigned char music_disabled, shadows, shell_marks, sharp_filter, glow, smoke;
    int player_count;
    unsigned char show_fps;
    int game_mode;
    int movement_scheme[2], aim_scheme[2];
    int configuring, pad_threshold, pad_center_x, pad_center_y;
    int pov_right, pov_left;
#if CL_BUILD >= 10400
    unsigned char direction_arrow;
#endif
    int display_bpp, screen_width, screen_height;
    bool windowed;
#if CL_BUILD >= 10400
    unsigned char sound_frequency_adjustment;
#endif
    unsigned char keys[2][5];
};
typedef char freeware_config_file_size[(sizeof(freeware_config_t) == (CL_BUILD == 10300 ? 0x54 : 0x58)) ? 1 : -1];
extern "C" freeware_config_t config_blob;

#endif
