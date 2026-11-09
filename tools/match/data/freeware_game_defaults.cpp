// Startup values of the original freeware EXEs.
// Each byte flag occupies one byte even where the next symbol is aligned.
#include "cl_build.h"
#include "crimsonland_types.h"

extern "C" {
float time_scale_factor = 1.0f;
float freeware_transition_alpha = 1.0f;
unsigned char freeware_menu_music_pending = 1;
int freeware_encounter_id = 1;
int freeware_encounter_page = 1;
int freeware_encounter_day = 1;
int game_state_id = 1;
unsigned char freeware_transition_pending = 1;
int freeware_bonus_fire = 1;
int freeware_bonus_freeze = 2;
int freeware_bonus_weapon = 3;
int freeware_bonus_nuke = 4;
int freeware_arena_width = 1024;
int freeware_arena_height = 1024;
unsigned char freeware_music_started = 1;

#if CL_BUILD == 10002
game_mode_id_t config_game_mode = GAME_MODE_SURVIVAL;
int config_movement_schemes[1] = {2};
unsigned char freeware_shadows = 1;
unsigned char freeware_glow = 1;
#endif

#if CL_BUILD < 10400
int freeware_music_channel_a = -1;
int freeware_music_channel_b = -1;
float freeware_music_volume_a = 1.0f;
#endif

#if CL_BUILD == 10300
float freeware_music_volume_b = 1.0f;
#endif

#if CL_BUILD >= 10300
int screen_width = 640;
int screen_height = 480;
int screenshot_file_index = 1;
float freeware_fps_min = 1000.0f;
int freeware_bonus_shield = 5;
int freeware_bonus_time = 6;
float freeware_editor_light = 1.0f;
float freeware_editor_alpha = 1.0f;
float freeware_editor_radius = 128.0f;
#endif

#if CL_BUILD == 10400
float screen_width_f = 640.0f;
float screen_height_f = 480.0f;
int freeware_console_creature_health = 100;
int freeware_console_creature_size = 40;
int freeware_rank = -1;
unsigned char freeware_music_fading[3] = {1, 1, 1};
char secret_hint_magic_paint[] = "With magic paint you can fix city walls. Yellow.";
#endif

} // extern "C"
