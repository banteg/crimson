#ifndef CRIMSONLAND_GAMEPLAY_H
#define CRIMSONLAND_GAMEPLAY_H

typedef struct IDirectSoundBuffer *LPDIRECTSOUNDBUFFER;

#include "crimsonland_types.h"

typedef enum creature_type_id_t {
    CREATURE_TYPE_ZOMBIE = 0,
    CREATURE_TYPE_LIZARD = 1,
    CREATURE_TYPE_ALIEN = 2,
    CREATURE_TYPE_SPIDER_SP1 = 3,
    CREATURE_TYPE_SPIDER_SP2 = 4,
    CREATURE_TYPE_TROOPER = 5,
} creature_type_id_t;

typedef enum creature_ai_mode_t {
    CREATURE_AI_ORBIT_PLAYER = 0,
    CREATURE_AI_ORBIT_PLAYER_TIGHT = 1,
    CREATURE_AI_CHASE_PLAYER = 2,
    CREATURE_AI_FOLLOW_LINK = 3,
    CREATURE_AI_LINK_GUARD = 4,
    CREATURE_AI_FOLLOW_LINK_TETHERED = 5,
    CREATURE_AI_ORBIT_LINK = 6,
    CREATURE_AI_HOLD_TIMER = 7,
    CREATURE_AI_ORBIT_PLAYER_WIDE = 8,
} creature_ai_mode_t;

typedef enum creature_flags_t {
    CREATURE_FLAG_SELF_DAMAGE_TICK = 0x01,
    CREATURE_FLAG_SELF_DAMAGE_TICK_STRONG = 0x02,
    CREATURE_FLAG_ANIM_PING_PONG = 0x04,
    CREATURE_FLAG_SPLIT_ON_DEATH = 0x08,
    CREATURE_FLAG_RANGED_ATTACK_SHOCK = 0x10,
    CREATURE_FLAG_ANIM_LONG_STRIP = 0x40,
    CREATURE_FLAG_AI7_LINK_TIMER = 0x80,
    CREATURE_FLAG_RANGED_ATTACK_VARIANT = 0x100,
    CREATURE_FLAG_BONUS_ON_DEATH = 0x400,
} creature_flags_t;

typedef enum spawn_id_t {
    SPAWN_ID_ZOMBIE_BOSS_SPAWNER_00 = 0x00,
    SPAWN_ID_SPIDER_SP2_SPLITTER_01 = 0x01,
    SPAWN_ID_UNUSED_02 = 0x02,
    SPAWN_ID_SPIDER_SP1_RANDOM_03 = 0x03,
    SPAWN_ID_LIZARD_RANDOM_04 = 0x04,
    SPAWN_ID_SPIDER_SP2_RANDOM_05 = 0x05,
    SPAWN_ID_ALIEN_RANDOM_06 = 0x06,
    SPAWN_ID_ALIEN_SPAWNER_CHILD_1D_FAST_07 = 0x07,
    SPAWN_ID_ALIEN_SPAWNER_CHILD_1D_SLOW_08 = 0x08,
    SPAWN_ID_ALIEN_SPAWNER_CHILD_1D_LIMITED_09 = 0x09,
    SPAWN_ID_ALIEN_SPAWNER_CHILD_32_SLOW_0A = 0x0a,
    SPAWN_ID_ALIEN_SPAWNER_CHILD_3C_SLOW_0B = 0x0b,
    SPAWN_ID_ALIEN_SPAWNER_CHILD_31_FAST_0C = 0x0c,
    SPAWN_ID_ALIEN_SPAWNER_CHILD_31_SLOW_0D = 0x0d,
    SPAWN_ID_ALIEN_SPAWNER_RING_24_0E = 0x0e,
    SPAWN_ID_ALIEN_CONST_BROWN_TRANSPARENT_0F = 0x0f,
    SPAWN_ID_ALIEN_SPAWNER_CHILD_32_FAST_10 = 0x10,
    SPAWN_ID_FORMATION_CHAIN_LIZARD_4_11 = 0x11,
    SPAWN_ID_FORMATION_RING_ALIEN_8_12 = 0x12,
    SPAWN_ID_FORMATION_CHAIN_ALIEN_10_13 = 0x13,
    SPAWN_ID_FORMATION_GRID_ALIEN_GREEN_14 = 0x14,
    SPAWN_ID_FORMATION_GRID_ALIEN_WHITE_15 = 0x15,
    SPAWN_ID_FORMATION_GRID_LIZARD_WHITE_16 = 0x16,
    SPAWN_ID_FORMATION_GRID_SPIDER_SP1_WHITE_17 = 0x17,
    SPAWN_ID_FORMATION_GRID_ALIEN_BRONZE_18 = 0x18,
    SPAWN_ID_FORMATION_RING_ALIEN_5_19 = 0x19,
    SPAWN_ID_AI1_ALIEN_BLUE_TINT_1A = 0x1a,
    SPAWN_ID_AI1_SPIDER_SP1_BLUE_TINT_1B = 0x1b,
    SPAWN_ID_AI1_LIZARD_BLUE_TINT_1C = 0x1c,
    SPAWN_ID_ALIEN_RANDOM_1D = 0x1d,
    SPAWN_ID_ALIEN_RANDOM_1E = 0x1e,
    SPAWN_ID_ALIEN_RANDOM_1F = 0x1f,
    SPAWN_ID_ALIEN_RANDOM_GREEN_20 = 0x20,
    SPAWN_ID_ALIEN_CONST_PURPLE_GHOST_21 = 0x21,
    SPAWN_ID_ALIEN_CONST_GREEN_GHOST_22 = 0x22,
    SPAWN_ID_ALIEN_CONST_GREEN_GHOST_SMALL_23 = 0x23,
    SPAWN_ID_ALIEN_CONST_GREEN_24 = 0x24,
    SPAWN_ID_ALIEN_CONST_GREEN_SMALL_25 = 0x25,
    SPAWN_ID_ALIEN_CONST_PALE_GREEN_26 = 0x26,
    SPAWN_ID_ALIEN_CONST_WEAPON_BONUS_27 = 0x27,
    SPAWN_ID_ALIEN_CONST_PURPLE_28 = 0x28,
    SPAWN_ID_ALIEN_CONST_GREY_BRUTE_29 = 0x29,
    SPAWN_ID_ALIEN_CONST_GREY_FAST_2A = 0x2a,
    SPAWN_ID_ALIEN_CONST_RED_FAST_2B = 0x2b,
    SPAWN_ID_ALIEN_CONST_RED_BOSS_2C = 0x2c,
    SPAWN_ID_ALIEN_CONST_CYAN_AI2_2D = 0x2d,
    SPAWN_ID_LIZARD_RANDOM_2E = 0x2e,
    SPAWN_ID_LIZARD_CONST_GREY_2F = 0x2f,
    SPAWN_ID_LIZARD_CONST_YELLOW_BOSS_30 = 0x30,
    SPAWN_ID_LIZARD_RANDOM_31 = 0x31,
    SPAWN_ID_SPIDER_SP1_RANDOM_32 = 0x32,
    SPAWN_ID_SPIDER_SP1_RANDOM_RED_33 = 0x33,
    SPAWN_ID_SPIDER_SP1_RANDOM_GREEN_34 = 0x34,
    SPAWN_ID_SPIDER_SP2_RANDOM_35 = 0x35,
    SPAWN_ID_ALIEN_AI7_ORBITER_36 = 0x36,
    SPAWN_ID_SPIDER_SP2_RANGED_VARIANT_37 = 0x37,
    SPAWN_ID_SPIDER_SP1_AI7_TIMER_38 = 0x38,
    SPAWN_ID_SPIDER_SP1_AI7_TIMER_WEAK_39 = 0x39,
    SPAWN_ID_SPIDER_SP1_CONST_SHOCK_BOSS_3A = 0x3a,
    SPAWN_ID_SPIDER_SP1_CONST_RED_BOSS_3B = 0x3b,
    SPAWN_ID_SPIDER_SP1_CONST_RANGED_VARIANT_3C = 0x3c,
    SPAWN_ID_SPIDER_SP1_RANDOM_3D = 0x3d,
    SPAWN_ID_SPIDER_SP1_CONST_WHITE_FAST_3E = 0x3e,
    SPAWN_ID_SPIDER_SP1_CONST_BROWN_SMALL_3F = 0x3f,
    SPAWN_ID_SPIDER_SP1_CONST_BLUE_40 = 0x40,
    SPAWN_ID_ZOMBIE_RANDOM_41 = 0x41,
    SPAWN_ID_ZOMBIE_CONST_GREY_42 = 0x42,
    SPAWN_ID_ZOMBIE_CONST_GREEN_BRUTE_43 = 0x43,
} spawn_id_t;

#ifdef __cplusplus
extern "C" {
#endif

extern int perk_id_fastloader;
extern int perk_id_antiperk;
extern int perk_id_instant_winner;
extern int perk_id_alternate_weapon;
extern int perk_id_plaguebearer;
extern int perk_id_poison_bullets;
extern int perk_id_regression_bullets;
extern int perk_id_ammunition_within;
extern int perk_id_ammo_maniac;
extern int perk_id_veins_of_poison;
extern int perk_id_bonus_economist;
extern int perk_id_bonus_magnet;
extern int perk_id_final_revenge;
extern int perk_id_my_favourite_weapon;
extern int perk_id_unstoppable;
extern int perk_id_thick_skinned;
extern int perk_id_highlander;
extern int perk_id_dodger;
extern int perk_id_ninja;
extern int perk_id_death_clock;
extern int perk_id_tough_reloader;
extern int perk_id_man_bomb;
extern int perk_id_fire_caugh;
extern int perk_id_living_fortress;
extern int perk_id_max;

extern player_state_t player_state_table[];
extern crimson_cfg_t config_blob;
extern int render_overlay_player_index;
extern int player_reset_reserved_zero;
extern unsigned char player_plaguebearer_active[];
extern float ui_mouse_x;
extern float ui_mouse_y;
extern float frame_dt;
extern float player_heading_turn_delta;
extern float bonus_weapon_power_up_timer;
extern float bonus_reflex_boost_timer;
extern float bonus_freeze_timer;
extern float bonus_energizer_timer;
extern float bonus_double_xp_timer;
extern highscore_record_t highscore_active_record;
extern char default_player_name[];
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
extern secondary_projectile_pool_t secondary_projectile_pool;
extern particle_t particle_pool[];
extern sprite_effect_t sprite_effect_pool[];
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
extern unsigned char survival_reward_damage_seen;
extern unsigned char creatures_any_active_flag;
extern unsigned char demo_mode_active;
extern int highscore_record_shots_fired;
extern int creature_spawned_count;
extern int shock_chain_links_left;
extern int shock_chain_projectile_id;
extern int camera_shake_pulses;
extern float camera_shake_timer;
extern int terrain_texture_width;
extern int terrain_texture_height;
extern int quest_fail_retry_count;
extern int survival_elapsed_ms;
extern player_aux_timer_t player_aux_timer;
extern int survival_spawn_stage;
extern int gameplay_run_reserved_zero;
extern unsigned char main_menu_full_version_layout_latch;
extern int creature_active_count;
extern int time_played_ms;
extern int quest_transition_timer_ms;

extern int sfx_ui_bonus;
extern int sfx_shockwave;
extern int sfx_shock_hit_01;
extern int sfx_explosion_medium;
extern int sfx_explosion_large;
extern int sfx_trooper_inpain_01;
extern int sfx_trooper_die_01;

extern int effect_template_flags;
extern effect_template_t effect_template;
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
extern effect_entry_t effect_discard_entry;
extern effect_pool_t effect_pool;
extern effect_entry_t *effect_free_list_head;
extern effect_id_entry_t effect_id_table[];

int perk_count_get(int perk_id);
unsigned char perk_can_offer(int perk_id);
int crt_rand(void);
bonus_entry_t *bonus_alloc_slot(void);
bonus_entry_t *bonus_spawn_at_pos(float *pos);
bonus_id_t bonus_pick_random_type(void);
int weapon_pick_random_available(void);
int console_printf(char *queue, char *fmt, ...);
int crt_sprintf(char *dst, const char *fmt, ...);
int game_is_full_version(void);
char *weapon_table_entry(int weapon_id);
void sfx_play(int sfx_id, float volume);
void sfx_play_panned(int sfx_id, float *pos, float volume);
void bonus_hud_slot_activate(char *label, int icon_id, float *timer, float *alt_timer);
void weapon_assign_player(int player_index, int weapon_id);
void effect_init_entry(effect_entry_t *entry);
void effect_free(effect_entry_t *entry);
effect_entry_t *effect_spawn(int effect_id, float *pos);
void effect_spawn_ion_hit_core(float *pos, float scale_step, float lifetime);
void effect_spawn_plasma_hit_core(float *pos, float scale_step, float lifetime);
void effect_spawn_freeze_shard(float *pos, float angle);
void effect_spawn_freeze_shatter(float *pos, float angle);
void effect_spawn_explosion_burst(float *pos, float scale);
int projectile_spawn(float *pos, float angle, int type_id, int owner_id);
int player_apply_move_with_spawn_avoidance(int player_index, float *pos, float *delta);
int creature_alloc_slot(void);
int creature_spawn_tinted(float *pos, float *rgba, int type_id);
int creature_spawn_slot_alloc(void);
int creature_find_nearest(float *pos, int exclude_id, float radius);
void creature_apply_damage(int creature_index, float damage, int damage_type, float *impulse);
void effect_spawn_burst(float *pos, int count);

typedef struct cvar_float_t {
    unsigned char _pad0[0x0c];
    float value;
} cvar_float_t;

extern cvar_float_t *cv_friendlyFire;
extern cvar_float_t *cv_verbose;

extern char console_log_queue;
extern char s_Unhandled_creatureType__00477758[];

#ifdef __cplusplus
}
#endif

#endif
