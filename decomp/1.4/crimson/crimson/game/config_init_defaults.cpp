#include "freeware_config.h"

extern "C" void config_init_defaults(void)
{
#if CL_BUILD >= 10400
    config_blob.audio_disabled = 0;
    config_blob.safe_mode = 0;
    config_blob.direction_arrow = 1;
    config_blob.sound_frequency_adjustment = 1;
#endif
    config_blob.pad_center_x = 0;
    config_blob.pad_center_y = 0;
    config_blob.pov_right = 9000;
    config_blob.pov_left = 27000;
    config_blob.pad_threshold = 100;
    config_blob.configuring = 0;
    config_blob.music_disabled = 0;
    config_blob.display_bpp = 32;
    config_blob.screen_width = 640;
    config_blob.screen_height = 480;
    config_blob.windowed = 0;
    config_blob.game_mode = 1;
    config_blob.shadows = 1;
    config_blob.shell_marks = 0;
    config_blob.sharp_filter = 0;
    config_blob.glow = 1;
    config_blob.movement_scheme[0] = 2;
    config_blob.movement_scheme[1] = 2;
    config_blob.aim_scheme[0] = 0;
    config_blob.aim_scheme[1] = 0;
    config_blob.smoke = 1;
    config_blob.player_count = 1;
    config_blob.show_fps = 0;
    config_blob.keys[0][0] = 0x11;
    config_blob.keys[0][1] = 0x1f;
    config_blob.keys[0][2] = 0x1e;
    config_blob.keys[0][3] = 0x20;
    config_blob.keys[0][4] = 0x0f;
    config_blob.keys[1][0] = 0xc8;
    config_blob.keys[1][1] = 0xd0;
    config_blob.keys[1][2] = 0xcb;
    config_blob.keys[1][3] = 0xcd;
    config_blob.keys[1][4] = 0x9d;
}
