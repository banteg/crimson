#ifndef CRIMSONLAND_GAMEPLAY_H
#define CRIMSONLAND_GAMEPLAY_H

typedef struct IDirectSoundBuffer *LPDIRECTSOUNDBUFFER;

#include "crimsonland_types.h"

#ifdef __cplusplus
extern "C" {
#endif

extern int perk_id_fastloader;
extern int perk_id_instant_winner;
extern int perk_id_alternate_weapon;
extern int perk_id_regression_bullets;
extern int perk_id_ammunition_within;
extern int perk_id_max;

extern player_state_t player_state_table[];
extern int render_overlay_player_index;
extern float frame_dt;
extern float player_heading_turn_delta;
extern float bonus_weapon_power_up_timer;
extern game_mode_id_t config_game_mode;
extern int quest_stage_major;
extern int quest_stage_minor;
extern int quest_unlock_index;
extern int quest_unlock_index_full;
extern quest_meta_t quest_selected_meta[];

extern weapon_stats_t weapon_table[];
extern perk_meta_t perk_meta_table[];
extern weapon_usage_counts_t weapon_usage_counts;
extern projectile_pool_t projectile_pool;
extern particle_t particle_pool[];
extern creature_t creature_pool[];
extern creature_spawn_slot_t creature_spawn_slot_table[];
extern bonus_pool_t bonus_pool;
extern bonus_entry_t bonus_pool_sentinel;
extern bonus_meta_t bonus_meta_table[];
extern char *bonus_label_points;
extern char bonus_label_format_buffer[];

extern unsigned char bonus_spawn_guard;
extern unsigned char creatures_any_active_flag;
extern int highscore_record_shots_fired;

int perk_count_get(int perk_id);
unsigned char perk_can_offer(int perk_id);
int crt_rand(void);
int console_printf(char *queue, char *fmt, ...);
int crt_sprintf(char *dst, const char *fmt, ...);
int game_is_full_version(void);
char *weapon_table_entry(int weapon_id);
void sfx_play_panned(int sfx_id, float *pos, float volume);

extern char console_log_queue;

#ifdef __cplusplus
}
#endif

#endif
