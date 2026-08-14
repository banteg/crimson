#ifndef CRIMSONLAND_GAME_STATE_OWNER_H
#define CRIMSONLAND_GAME_STATE_OWNER_H

/*
 * Target-era layout of the contiguous gameplay run state at 0x00486fa8.
 * The authenticated 2003 game_t declaration has the same member order after
 * removing its obsolete master_scale field.  Semantic names below retain the
 * identities recovered for 1.9.93 while restoring that aggregate ownership.
 */
typedef struct gameplay_run_state_original_t {
    unsigned char survival_reward_handout_enabled;
    unsigned char survival_reward_handout_aux_enabled;
    unsigned char main_menu_full_version_layout_latch;
    unsigned char pad_03;
    int perk_pending_count;
    unsigned char perk_choices_dirty;
    unsigned char pad_09[3];
    int creature_spawned_count;
    int survival_reward_weapon_guard_id;
    int shock_chain_links_left;
    int shock_chain_projectile_id;
    int survival_spawn_cooldown;
    int plaguebearer_infection_count;
    int creature_active_count;
    int quest_spawn_timeline;
    int quest_spawn_total_creatures;
    int tutorial_stage_index;
    int tutorial_stage_timer;
    int tutorial_stage_transition_timer;
    unsigned char survival_reward_fire_seen;
    unsigned char survival_reward_damage_seen;
    unsigned char pad_3e[2];
    vec2f_t survival_recent_death_pos[3];
    int survival_recent_death_count;
    int quest_stage_major;
    int quest_stage_minor;
    unsigned char creatures_any_active_flag;
    unsigned char demo_mode_active;
    unsigned char time_scale_active;
    unsigned char pad_67;
    float time_scale_factor;
    float bonus_reflex_boost_timer;
    float bonus_freeze_timer;
    float bonus_weapon_power_up_timer;
    float bonus_energizer_timer;
    float bonus_double_xp_timer;
    int gameplay_run_reserved_zero;
    unsigned char screen_fade_ramp_flag;
    unsigned char pad_85[3];
    int quest_spawn_last_time_ms;
    int quest_unlock_index;
    int quest_unlock_index_full;
    unsigned char bonus_spawn_guard;
    unsigned char pad_95[3];
    highscore_record_t highscore_active_record;
    int quest_transition_timer_ms;
    weapon_usage_time_t weapon_usage_time;
    int time_played_ms;
    int survival_spawn_stage;
    int quest_fail_retry_count;
} gameplay_run_state_original_t;

#ifdef __cplusplus
extern "C" {
#endif
extern unsigned char survival_reward_handout_enabled;
#ifdef __cplusplus
}
#endif

#define gameplay_run_state \
    (*(gameplay_run_state_original_t *)&survival_reward_handout_enabled)

#ifdef CRIMSONLAND_USE_ORIGINAL_GAME_OWNER
#define perk_pending_count gameplay_run_state.perk_pending_count
#define perk_choices_dirty gameplay_run_state.perk_choices_dirty
#define creature_spawned_count gameplay_run_state.creature_spawned_count
#define survival_reward_weapon_guard_id \
    gameplay_run_state.survival_reward_weapon_guard_id
#define shock_chain_links_left gameplay_run_state.shock_chain_links_left
#define shock_chain_projectile_id gameplay_run_state.shock_chain_projectile_id
#define survival_spawn_cooldown gameplay_run_state.survival_spawn_cooldown
#define plaguebearer_infection_count \
    gameplay_run_state.plaguebearer_infection_count
#define creature_active_count gameplay_run_state.creature_active_count
#define quest_spawn_timeline gameplay_run_state.quest_spawn_timeline
#define quest_spawn_total_creatures \
    gameplay_run_state.quest_spawn_total_creatures
#define tutorial_stage_index gameplay_run_state.tutorial_stage_index
#define tutorial_stage_timer gameplay_run_state.tutorial_stage_timer
#define tutorial_stage_transition_timer \
    gameplay_run_state.tutorial_stage_transition_timer
#define survival_reward_fire_seen gameplay_run_state.survival_reward_fire_seen
#define survival_reward_damage_seen \
    gameplay_run_state.survival_reward_damage_seen
#define survival_recent_death_count \
    gameplay_run_state.survival_recent_death_count
#define creatures_any_active_flag gameplay_run_state.creatures_any_active_flag
#define demo_mode_active gameplay_run_state.demo_mode_active
#define time_scale_active gameplay_run_state.time_scale_active
#define time_scale_factor gameplay_run_state.time_scale_factor
#define bonus_reflex_boost_timer gameplay_run_state.bonus_reflex_boost_timer
#define bonus_freeze_timer gameplay_run_state.bonus_freeze_timer
#define bonus_weapon_power_up_timer \
    gameplay_run_state.bonus_weapon_power_up_timer
#define bonus_energizer_timer gameplay_run_state.bonus_energizer_timer
#define bonus_double_xp_timer gameplay_run_state.bonus_double_xp_timer
#define gameplay_run_reserved_zero gameplay_run_state.gameplay_run_reserved_zero
#define screen_fade_ramp_flag gameplay_run_state.screen_fade_ramp_flag
#define quest_spawn_last_time_ms gameplay_run_state.quest_spawn_last_time_ms
#define quest_unlock_index gameplay_run_state.quest_unlock_index
#define quest_unlock_index_full gameplay_run_state.quest_unlock_index_full
#define bonus_spawn_guard gameplay_run_state.bonus_spawn_guard
#define highscore_active_record gameplay_run_state.highscore_active_record
#define quest_transition_timer_ms gameplay_run_state.quest_transition_timer_ms
#define weapon_usage_time gameplay_run_state.weapon_usage_time
#define time_played_ms gameplay_run_state.time_played_ms
#define survival_spawn_stage gameplay_run_state.survival_spawn_stage
#define quest_fail_retry_count gameplay_run_state.quest_fail_retry_count
#endif

#endif
