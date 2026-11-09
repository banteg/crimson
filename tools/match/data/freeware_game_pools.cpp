// Freeware static storage. Its constructors and startup loops run after the image is loaded.
#include "crimsonland_types.h"
#include "../../../decomp/1.4/crimson/crimson/highscore/freeware_score.h"

extern "C" {
creature_t creature_pool[CL_BUILD == 10002 ? 128 : 512];
#if CL_BUILD == 10002
creature_t unused_sfx_prefix_creature;
#endif
projectile_pool_t projectile_pool;
freeware_player_t player_state_table[2];
particle_t particle_pool[128];
vec2f_t freeware_atlas_uv[64];

#if CL_BUILD > 10002
secondary_projectile_pool_t secondary_projectile_pool;
sprite_effect_t sprite_effect_pool[CL_BUILD == 10300 ? 256 : 384];
fx_queue_entry_t fx_queue[CL_BUILD == 10300 ? 32 : 64];
#endif

// These queues clamp the next write index to capacity - 1.
vec2f_t freeware_blood_positions[64];
vec2f_t freeware_shell_positions[32];
vec2f_t freeware_corpse_positions[64];
effect_color_t freeware_corpse_colors[64];
float freeware_corpse_angles[64];
float freeware_corpse_sizes[64];
int freeware_corpse_species[64];

freeware_score_entry freeware_score_table[100];
freeware_score_entry freeware_last_score;
unsigned char perk_choice_flags[CL_BUILD == 10400 ? 48 : 32];
#if CL_BUILD > 10002
char freeware_score_key[243];
float freeware_fps[50];
#endif

#if CL_BUILD == 10002
char *freeware_main_labels[6], *freeware_option_labels[9], *freeware_town_choices[3];
#elif CL_BUILD == 10300
char *freeware_main_labels[7], *freeware_option_labels[11];
#else
char *freeware_main_labels[8], *freeware_option_labels[12], *freeware_online_labels[5];
float freeware_snow_y[1024];
#endif
}
