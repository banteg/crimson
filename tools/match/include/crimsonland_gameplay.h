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
extern int perk_id_bonus_economist;
extern int perk_id_max;

extern player_state_t player_state_table[];
extern crimson_cfg_t config_blob;
extern int render_overlay_player_index;
extern float frame_dt;
extern float player_heading_turn_delta;
extern float bonus_weapon_power_up_timer;
extern float bonus_reflex_boost_timer;
extern float bonus_freeze_timer;
extern float bonus_energizer_timer;
extern float bonus_double_xp_timer;
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
extern char *bonus_label_reflex_boost;
extern char *bonus_label_weapon_power_up;
extern char *bonus_label_speed;
extern char *bonus_label_freeze;
extern char *bonus_label_shield;
extern char *bonus_label_fire_bullets;
extern char *bonus_label_energizer;
extern char *bonus_label_double_experience;
extern char bonus_label_format_buffer[];
extern int bonus_icon_reflex_boost;
extern int bonus_icon_weapon_power_up;
extern int bonus_icon_speed;
extern int bonus_icon_freeze;
extern int bonus_icon_shield;
extern int bonus_icon_fire_bullets;
extern int bonus_icon_energizer;
extern int bonus_icon_double_experience;

extern unsigned char bonus_spawn_guard;
extern unsigned char creatures_any_active_flag;
extern int highscore_record_shots_fired;
extern int shock_chain_links_left;
extern int shock_chain_projectile_id;
extern int camera_shake_pulses;
extern float camera_shake_timer;

extern int sfx_ui_bonus;
extern int sfx_shockwave;
extern int sfx_shock_hit_01;
extern int sfx_explosion_medium;
extern int sfx_explosion_large;

extern int effect_template_flags;
extern float effect_template_color_r;
extern float effect_template_color_g;
extern float effect_template_color_b;
extern float effect_template_color_a;
extern float effect_template_lifetime;
extern float effect_template_age;
extern float effect_template_half_width;
extern float effect_template_half_height;
extern float effect_template_rotation;
extern float effect_template_vel_x;
extern float effect_template_vel_y;
extern float effect_template_scale_step;

int perk_count_get(int perk_id);
unsigned char perk_can_offer(int perk_id);
int crt_rand(void);
int console_printf(char *queue, char *fmt, ...);
int crt_sprintf(char *dst, const char *fmt, ...);
int game_is_full_version(void);
char *weapon_table_entry(int weapon_id);
void sfx_play(int sfx_id, float volume);
void sfx_play_panned(int sfx_id, float *pos, float volume);
void bonus_hud_slot_activate(char *label, int icon_id, float *timer, float *alt_timer);
void weapon_assign_player(int player_index, int weapon_id);
void effect_spawn(int effect_id, float *pos);
void effect_spawn_freeze_shard(float *pos, float angle);
void effect_spawn_freeze_shatter(float *pos, float angle);
void effect_spawn_explosion_burst(float *pos, float scale);
int projectile_spawn(float *pos, float angle, int type_id, int owner_id);
int creature_find_nearest(float *pos, int exclude_id, float radius);
void creature_apply_damage(int creature_index, float damage, int damage_type, float *impulse);

typedef struct cvar_float_t {
    unsigned char _pad0[0x0c];
    float value;
} cvar_float_t;

extern cvar_float_t *cv_friendlyFire;

extern char console_log_queue;

#ifdef __cplusplus
}
#endif

#endif
