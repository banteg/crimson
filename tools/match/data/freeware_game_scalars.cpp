// Zero-initialized state accessed by the matched freeware game functions.
#include "crimsonland_types.h"
#include <windows.h>

class IGrim2D_cpp;
struct freeware_level_map;

#if CL_BUILD == 10400
#include "../../../decomp/1.4/crimson/sfx_loader/sfx_loader.h"
// freeware_console_cmd_loadtile passes this packed header to fread.
#pragma pack(push, 1)
struct freeware_tile_header_t {
    unsigned char image_info[12];
    unsigned short width;
    unsigned short height;
    unsigned char bits_per_pixel;
    unsigned char descriptor;
};
#pragma pack(pop)
#endif

// The module handle in grim_load_interface has C++ linkage.
HMODULE grim_dll_module_handle;

extern "C" {
int aim64_texture;
float bonus_fire_bullets_timer;
float bonus_freeze_timer;
int creature_spawned_count;
int current_player_index;
float frame_dt;
vec2f_t freeware_aim_screen;
float freeware_berserk_timer;
int freeware_blood_count;
int freeware_blood_texture;
int freeware_bullet_icon;
int freeware_bullet_texture;
vec2f_t freeware_camera;
int freeware_corpse_count;
int freeware_creature_texture;
unsigned char freeware_credits_open;
// Both UV corners are stored and read by the quad renderer.
vec2f_t freeware_draw_point[2];
float freeware_elapsed_seconds;
unsigned char freeware_encounter_active;
unsigned char freeware_game_active;
float freeware_jinx_timer;
unsigned char freeware_level_up_reset_byte;
float freeware_logo_angle;
unsigned char freeware_logo_visible;
float freeware_name_alpha;
int freeware_name_length;
float freeware_next_spawn;
int freeware_no_pickup;
unsigned char freeware_options_open;
int freeware_particle_texture;
int freeware_pending_perks;
float freeware_perk_choice_timer;
int freeware_perk_hover;
int freeware_pickup_id;
vec2f_t freeware_pickup_position;
float freeware_pickup_time;
int freeware_player_texture;
unsigned char freeware_safe_mode;
unsigned char freeware_scores_closing;
unsigned char freeware_scores_open;
int freeware_shell_count;
float freeware_simulation_clock;
unsigned char freeware_spawn_enabled;
float freeware_state_since;
IGrim2D_cpp *grim_interface_ptr;
int perk_id_almost_invisible;
int perk_id_berserk_attack;
int perk_id_bloody_mess;
int perk_id_count;
int perk_id_fastloader;
int perk_id_fastshot;
int perk_id_grim_deal;
int perk_id_instant_winner;
int perk_id_jinxed;
int perk_id_long_distance_runner;
int perk_id_plaguebearer;
int perk_id_radioactive;
int perk_id_reflex_boosted;
int perk_id_see_health;
int perk_id_sharpshooter;
int perk_id_spontaneously_combusteous;
int terrain_render_target;
int world_arrow_marker_texture;

#if CL_BUILD >= 10300
float bonus_reflex_boost_timer;
int freeware_assembly_sequence;
unsigned char freeware_audio_disabled;
unsigned char freeware_birthday;
float freeware_bomb_age;
vec2f_t freeware_bomb_position;
int freeware_bonus_count;
unsigned char freeware_calibrating;
vec2f_t freeware_camera_shake;
float freeware_camera_timer;
freeware_level_map *freeware_current_map;
int freeware_editor_brush;
int freeware_editor_layer;
float freeware_editor_rotation;
int freeware_fps_count;
float freeware_fps_max;
float freeware_hud_xp_timer;
int freeware_ice_texture;
effect_color_t freeware_ice_tint;
int freeware_kills;
int freeware_level_number;
int freeware_levels_sequence;
int freeware_low_fps_frames;
int freeware_menu_selected;
float freeware_mouse_dx;
float freeware_mouse_dy;
unsigned char freeware_pause_perks;
int freeware_pickup_weapon;
unsigned char freeware_rebinding;
unsigned char freeware_score_corrupt;
float freeware_score_scroll;
unsigned char freeware_see_through;
int freeware_setup_step;
float freeware_xp_timer;
int fx_queue_count;
int highscore_record_hits;
int highscore_record_shots_fired;
int perk_id_ammo_maniac;
int perk_id_anxious_loader;
int perk_id_evil_eyes;
int perk_id_final_revenge;
int perk_id_infernal_contract;
int perk_id_lean_mean_exp_machine;
int perk_id_perk_expert;
int plaguebearer_infection_count;
#endif

#if CL_BUILD == 10002
unsigned char freeware_filter_sharp;
unsigned char freeware_shell_marks;
unsigned char freeware_show_fps;
int perk_id_timebender;
#endif

#if CL_BUILD == 10300
int perk_id_reserved_22;
#endif

#if CL_BUILD == 10400
unsigned char audio_resource_pack_available;
int console_height_px;
unsigned char console_open_flag;
float frame_dt_copy;
unsigned char freeware_cheated;
unsigned char freeware_christmas;
IGrim2D_cpp *freeware_console_grim;
effect_color_t freeware_creature_spawn_tint;
float freeware_fade_time;
vec2f_t freeware_first_kill_position;
int freeware_first_kill_xp;
float freeware_hit_sound_timer;
unsigned char freeware_memorial;
unsigned char freeware_music_unavailable;
unsigned char freeware_online_open;
unsigned char freeware_open_site;
unsigned char freeware_player_moved;
unsigned char freeware_rainbow_armed;
// The frame dispatcher initializes all eight flags in a counted loop.
unsigned char freeware_random_flags[8];
float freeware_real_clock;
float freeware_revive_timer;
unsigned char freeware_score_highlighted;
unsigned char freeware_secret_weapon_unlocked;
void (*freeware_sfx_free)(void *sample);
void *(*freeware_sfx_get)(const char *name);
unsigned char (*freeware_sfx_init)(int frequency, int bits);
signed char (*freeware_sfx_is_playing)(int channel);
bool (*freeware_sfx_load)(const char *filename, const char *name);
HMODULE freeware_sfx_module;
int (*freeware_sfx_play)(void *sample, int paused);
void (*freeware_sfx_set_frequency)(int channel, int frequency);
void (*freeware_sfx_set_pan)(int channel, float pan);
unsigned char (*freeware_sfx_set_paq)(const char *filename);
void (*freeware_sfx_set_paused)(int channel, unsigned char paused);
void (*freeware_sfx_set_position)(int channel, unsigned int offset);
void (*freeware_sfx_set_volume)(int channel, float volume);
void (*freeware_sfx_shutdown)();
void (*freeware_sfx_stop_channel)(int channel);
unsigned char freeware_show_secret_hints;
unsigned char freeware_solstice;
freeware_tile_header_t freeware_tile_header;
int freeware_tips_sequence;
char *freeware_update_info;
int perk_id_fatal_lottery;
int perk_id_reserved_33;
int perk_id_test;
int perk_id_weapon_assault_rifle;
int perk_id_weapon_shotgun;
unsigned char quit_requested;
unsigned char time_scale_active;
#endif
} // extern "C"
