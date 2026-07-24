#include "crimsonland_gameplay.h"
#include "grim2d_cpp.h"

#include <string.h>

struct reset_vec2_t {
    float x;
    float y;

    reset_vec2_t(float x_value, float y_value) : x(x_value), y(y_value) {}
};

extern "C" {

extern IGrim2D_cpp *grim_interface_ptr;
extern bonus_hud_slot_t bonus_hud_slot_table[];
extern unsigned char player_overlay_suppressed_latch;
extern int quest_spawn_timeline;
extern int shock_chain_links_left;
extern int survival_reward_weapon_guard_id;
extern int creature_spawned_count;
extern int survival_recent_death_count;
extern unsigned char survival_reward_damage_seen;
extern unsigned char survival_reward_fire_seen;
extern unsigned char survival_reward_handout_aux_enabled;
extern unsigned char survival_reward_handout_enabled;
extern int tutorial_stage_index;
extern int tutorial_stage_timer;
extern int tutorial_stage_transition_timer;
extern int quest_transition_timer_ms;
extern float bonus_double_xp_timer;
extern int survival_spawn_stage;
extern int camera_shake_pulses;
extern int creature_type_count;
extern creature_type_table_t creature_type_table;

extern int sfx_zombie_attack_01;
extern int sfx_zombie_attack_02;
extern int sfx_zombie_die_01;
extern int sfx_zombie_die_02;
extern int sfx_zombie_die_03;
extern int sfx_zombie_die_04;
extern int sfx_lizard_attack_01;
extern int sfx_lizard_attack_02;
extern int sfx_lizard_die_01;
extern int sfx_lizard_die_02;
extern int sfx_lizard_die_03;
extern int sfx_lizard_die_04;
extern int sfx_spider_attack_01;
extern int sfx_spider_attack_02;
extern int sfx_spider_die_01;
extern int sfx_spider_die_02;
extern int sfx_spider_die_03;
extern int sfx_spider_die_04;
extern int sfx_alien_attack_01;
extern int sfx_alien_attack_02;
extern int sfx_alien_die_01;
extern int sfx_alien_die_02;
extern int sfx_alien_die_03;
extern int sfx_alien_die_04;
extern int sfx_trooper_die_01;
extern int sfx_trooper_die_02;
extern int sfx_trooper_die_03;

extern unsigned char perk_choices_dirty;
extern unsigned char bonus_spawn_guard;
extern weapon_usage_time_t weapon_usage_time;
extern int terrain_texture_width;
extern int terrain_texture_height;
extern reset_vec2_t camera_offset;
extern int perk_pending_count;
extern int survival_spawn_cooldown;
extern unsigned char creatures_any_active_flag;
extern unsigned char time_scale_active;
extern float time_scale_factor;
extern float bonus_reflex_boost_timer;
extern float bonus_weapon_power_up_timer;
extern float bonus_energizer_timer;
extern int plaguebearer_infection_count;
extern int perk_doctor_target_creature_id;
extern highscore_record_t highscore_active_record;
extern float gameplay_reset_unused_timer;
extern float bonus_freeze_timer;
extern float perk_jinxed_proc_timer_s;
extern float bonus_update_phase_accumulator;
extern int perk_prompt_timer;
extern bonus_pool_t bonus_pool;
extern projectile_pool_t projectile_pool;
extern sprite_effect_t sprite_effect_pool[];
extern secondary_projectile_pool_t secondary_projectile_pool;
extern creature_t creature_pool[];
extern creature_spawn_slot_t creature_spawn_slot_table[];
extern int fx_queue_rotated;
extern int fx_queue_count;

void bonus_reset_availability(void);
void weapon_table_init(void);
void weapon_refresh_available(void);
void perks_rebuild_available(void);
void effect_defaults_reset(void);
void projectile_reset_pools(void);
void player_reset_all(void);
void terrain_generate_random(void);
int crt_rand(void);

void gameplay_reset_state(void)
{
    player_overlay_suppressed_latch = 0;
    for (int slot_index = 0; slot_index < 16; ++slot_index) {
        bonus_hud_slot_t *slot = &bonus_hud_slot_table[slot_index];
        slot->slide.field_0x1c = 5.0f;
        slot->active = 0;
        slot->slide.slide_x = 0.0f;
        slot->slide.icon_id = 1;
        slot->slide.label = "Empty";
        slot->slide.field_0x08 = 1.0f;
    }

    quest_spawn_timeline = 0;
    shock_chain_links_left = 0;
    survival_reward_weapon_guard_id = 1;
    creature_spawned_count = 0;
    survival_recent_death_count = 0;
    survival_reward_damage_seen = 0;
    survival_reward_fire_seen = 0;
    survival_reward_handout_aux_enabled = 1;
    survival_reward_handout_enabled = 1;
    tutorial_stage_index = -1;
    tutorial_stage_timer = 0;
    tutorial_stage_transition_timer = -1000;
    quest_transition_timer_ms = -1;
    bonus_double_xp_timer = 0.0f;
    survival_spawn_stage = 0;
    camera_shake_pulses = 0;

    bonus_reset_availability();
    creature_type_count = 6;

    creature_type_table[CREATURE_TYPE_ZOMBIE].texture_handle =
        grim_interface_ptr->grim_get_texture_handle("zombie");
    creature_type_table[CREATURE_TYPE_ZOMBIE].sfx_bank_b[0] =
        sfx_zombie_attack_01;
    creature_type_table[CREATURE_TYPE_ZOMBIE].sfx_bank_b[1] =
        sfx_zombie_attack_02;
    creature_type_table[CREATURE_TYPE_ZOMBIE].sfx_bank_a[0] = sfx_zombie_die_01;
    creature_type_table[CREATURE_TYPE_ZOMBIE].sfx_bank_a[1] = sfx_zombie_die_02;
    creature_type_table[CREATURE_TYPE_ZOMBIE].field_0x20 = 1.0f;
    creature_type_table[CREATURE_TYPE_ZOMBIE].anim_rate = 1.2f;
    creature_type_table[CREATURE_TYPE_ZOMBIE].sfx_bank_a[2] = sfx_zombie_die_03;
    creature_type_table[CREATURE_TYPE_ZOMBIE].sfx_bank_a[3] = sfx_zombie_die_04;
    creature_type_table[CREATURE_TYPE_ZOMBIE].base_frame = 32;
    creature_type_table[CREATURE_TYPE_ZOMBIE].corpse_frame = 0;

    creature_type_table[CREATURE_TYPE_LIZARD].texture_handle =
        grim_interface_ptr->grim_get_texture_handle("lizard");
    creature_type_table[CREATURE_TYPE_LIZARD].sfx_bank_b[0] =
        sfx_lizard_attack_01;
    creature_type_table[CREATURE_TYPE_LIZARD].sfx_bank_b[1] =
        sfx_lizard_attack_02;
    creature_type_table[CREATURE_TYPE_LIZARD].sfx_bank_a[0] = sfx_lizard_die_01;
    creature_type_table[CREATURE_TYPE_LIZARD].field_0x20 = 1.0f;
    creature_type_table[CREATURE_TYPE_LIZARD].anim_rate = 1.6f;
    creature_type_table[CREATURE_TYPE_LIZARD].sfx_bank_a[1] = sfx_lizard_die_02;
    creature_type_table[CREATURE_TYPE_LIZARD].sfx_bank_a[2] = sfx_lizard_die_03;
    creature_type_table[CREATURE_TYPE_LIZARD].sfx_bank_a[3] = sfx_lizard_die_04;
    creature_type_table[CREATURE_TYPE_LIZARD].anim_flags = 1;
    creature_type_table[CREATURE_TYPE_LIZARD].base_frame = 16;
    creature_type_table[CREATURE_TYPE_LIZARD].corpse_frame = 3;

    creature_type_table[CREATURE_TYPE_SPIDER_SP1].texture_handle =
        grim_interface_ptr->grim_get_texture_handle("spider_sp1");
    creature_type_table[CREATURE_TYPE_SPIDER_SP1].sfx_bank_b[0] =
        sfx_spider_attack_01;
    creature_type_table[CREATURE_TYPE_SPIDER_SP1].sfx_bank_b[1] =
        sfx_spider_attack_02;
    creature_type_table[CREATURE_TYPE_SPIDER_SP1].field_0x20 = 1.0f;
    creature_type_table[CREATURE_TYPE_SPIDER_SP1].anim_rate = 1.5f;
    creature_type_table[CREATURE_TYPE_SPIDER_SP1].sfx_bank_a[0] = sfx_spider_die_01;
    creature_type_table[CREATURE_TYPE_SPIDER_SP1].sfx_bank_a[1] = sfx_spider_die_02;
    creature_type_table[CREATURE_TYPE_SPIDER_SP1].sfx_bank_a[2] = sfx_spider_die_03;
    creature_type_table[CREATURE_TYPE_SPIDER_SP1].sfx_bank_a[3] = sfx_spider_die_04;
    creature_type_table[CREATURE_TYPE_SPIDER_SP1].anim_flags = 1;
    creature_type_table[CREATURE_TYPE_SPIDER_SP1].base_frame = 16;
    creature_type_table[CREATURE_TYPE_SPIDER_SP1].corpse_frame = 1;

    creature_type_table[CREATURE_TYPE_SPIDER_SP2].texture_handle =
        grim_interface_ptr->grim_get_texture_handle("spider_sp2");
    creature_type_table[CREATURE_TYPE_SPIDER_SP2].sfx_bank_b[0] =
        sfx_spider_attack_01;
    creature_type_table[CREATURE_TYPE_SPIDER_SP2].sfx_bank_b[1] =
        sfx_spider_attack_02;
    creature_type_table[CREATURE_TYPE_SPIDER_SP2].sfx_bank_a[0] = sfx_spider_die_01;
    creature_type_table[CREATURE_TYPE_SPIDER_SP2].field_0x20 = 1.0f;
    creature_type_table[CREATURE_TYPE_SPIDER_SP2].anim_rate = 1.5f;
    creature_type_table[CREATURE_TYPE_SPIDER_SP2].sfx_bank_a[1] = sfx_spider_die_02;
    creature_type_table[CREATURE_TYPE_SPIDER_SP2].sfx_bank_a[2] = sfx_spider_die_03;
    creature_type_table[CREATURE_TYPE_SPIDER_SP2].sfx_bank_a[3] = sfx_spider_die_04;
    creature_type_table[CREATURE_TYPE_SPIDER_SP2].anim_flags = 1;
    creature_type_table[CREATURE_TYPE_SPIDER_SP2].base_frame = 16;
    creature_type_table[CREATURE_TYPE_SPIDER_SP2].corpse_frame = 2;

    creature_type_table[CREATURE_TYPE_ALIEN].texture_handle =
        grim_interface_ptr->grim_get_texture_handle("alien");
    creature_type_table[CREATURE_TYPE_ALIEN].sfx_bank_b[0] = sfx_alien_attack_01;
    creature_type_table[CREATURE_TYPE_ALIEN].sfx_bank_b[1] = sfx_alien_attack_02;
    creature_type_table[CREATURE_TYPE_ALIEN].sfx_bank_a[0] = sfx_alien_die_01;
    creature_type_table[CREATURE_TYPE_ALIEN].sfx_bank_a[1] = sfx_alien_die_02;
    creature_type_table[CREATURE_TYPE_ALIEN].sfx_bank_a[2] = sfx_alien_die_03;
    creature_type_table[CREATURE_TYPE_ALIEN].sfx_bank_a[3] = sfx_alien_die_04;
    creature_type_table[CREATURE_TYPE_TROOPER].sfx_bank_a[0] = sfx_trooper_die_01;
    creature_type_table[CREATURE_TYPE_ALIEN].field_0x20 = 1.0f;
    creature_type_table[CREATURE_TYPE_ALIEN].anim_rate = 1.35f;
    creature_type_table[CREATURE_TYPE_ALIEN].anim_flags = 0;
    creature_type_table[CREATURE_TYPE_ALIEN].base_frame = 32;
    creature_type_table[CREATURE_TYPE_ALIEN].corpse_frame = 4;
    creature_type_table[CREATURE_TYPE_TROOPER].sfx_bank_a[1] = sfx_trooper_die_02;
    creature_type_table[CREATURE_TYPE_TROOPER].sfx_bank_a[2] = sfx_trooper_die_03;
    creature_type_table[CREATURE_TYPE_TROOPER].corpse_frame = 7;
    creature_type_table[CREATURE_TYPE_TROOPER].texture_handle =
        grim_interface_ptr->grim_get_texture_handle("trooper");

    perk_choices_dirty = 1;
    bonus_spawn_guard = 0;
    memset(weapon_usage_time, 0, sizeof(weapon_usage_time));
    camera_offset = reset_vec2_t(
        terrain_texture_width * 0.5f,
        terrain_texture_height * 0.5f);
    weapon_table_init();
    weapon_refresh_available();
    perks_rebuild_available();
    effect_defaults_reset();

    perk_pending_count = 0;
    survival_spawn_cooldown = 0;
    creatures_any_active_flag = 0;
    time_scale_active = 0;
    time_scale_factor = 1.0f;
    bonus_reflex_boost_timer = 0.0f;
    bonus_weapon_power_up_timer = 0.0f;
    bonus_energizer_timer = 0.0f;
    plaguebearer_infection_count = 0;
    perk_doctor_target_creature_id = -1;

    highscore_active_record.hardcore_marker = 0;
    highscore_active_record.survival_elapsed_ms = 0;
    highscore_active_record.score_xp = 0;
    highscore_active_record.quest_stage_minor = 0;
    highscore_active_record.quest_stage_major = 0;
    highscore_active_record.game_mode_id = 0;
    highscore_active_record.most_used_weapon_id = 0;
    highscore_active_record.creature_kill_count = 0;
    highscore_active_record.shots_hit = 0;
    highscore_active_record.shots_fired = 0;
    highscore_active_record.date_checksum = 0;
    highscore_active_record.year_offset = 0;
    highscore_active_record.month = 0;
    highscore_active_record.day = 0;
    highscore_active_record.flags = 0;
    int random_tag = crt_rand() & 0x0fee050f;
    gameplay_reset_unused_timer = 0.0f;
    highscore_active_record.random_tag = random_tag;

    bonus_freeze_timer = 0.0f;
    perk_jinxed_proc_timer_s = 0.0f;
    bonus_update_phase_accumulator = -1.0f;
    perk_prompt_timer = 0;
    projectile_reset_pools();
    player_reset_all();
    memset(player_aux_timer, 0, sizeof(player_aux_timer));

    for (int player_index = 0; player_index < 2; ++player_index) {
        player_state_t *player = &player_state_table[player_index];
        *(reset_vec2_t *)&player->move_target_x =
            reset_vec2_t(-1.0f, -1.0f);
        player->low_health_timer = 100.0f;
        player->fire_bullets_timer = 0.0f;
    }

    bonus_entry_t *bonus = &bonus_pool[0];
    do {
        bonus->bonus_id = BONUS_ID_NONE;
        ++bonus;
    } while ((int)bonus < (int)&bonus_pool[16]);

    projectile_t *projectile = &projectile_pool[0];
    do {
        projectile->active = 0;
        ++projectile;
    } while ((int)projectile < (int)&projectile_pool[0x60]);

    sprite_effect_t *sprite = &sprite_effect_pool[0];
    do {
        sprite->active = 0;
        ++sprite;
    } while ((int)sprite < (int)&sprite_effect_pool[0x180]);

    secondary_projectile_t *secondary = &secondary_projectile_pool[0];
    do {
        secondary->active = 0;
        ++secondary;
    } while ((int)secondary < (int)&secondary_projectile_pool[0x40]);

    for (int creature_id = 0; creature_id < 0x180; ++creature_id) {
        creature_pool[creature_id].hit_flash_timer = 0.0f;
        creature_pool[creature_id].active = 0;
        if (config_blob.player_count != 0) {
            creature_pool[creature_id].target_player =
                creature_id % config_blob.player_count;
        } else {
            creature_pool[creature_id].target_player = 0;
        }
        creature_pool[creature_id].state_flag = 1;
        creature_pool[creature_id].flags = 0;
        creature_pool[creature_id].anim_phase = (float)(crt_rand() % 31);
    }

    creature_spawn_slot_t *spawn = &creature_spawn_slot_table[0];
    do {
        spawn->owner = 0;
        ++spawn;
    } while ((int)spawn < (int)&creature_spawn_slot_table[32]);

    fx_queue_rotated = 0;
    fx_queue_count = 0;

    highscore_active_record.hardcore_marker = 0;
    highscore_active_record.survival_elapsed_ms = 0;
    highscore_active_record.score_xp = 0;
    highscore_active_record.quest_stage_minor = 0;
    highscore_active_record.quest_stage_major = 0;
    highscore_active_record.game_mode_id = 0;
    highscore_active_record.most_used_weapon_id = 0;
    highscore_active_record.creature_kill_count = 0;
    highscore_active_record.shots_hit = 0;
    highscore_active_record.shots_fired = 0;
    highscore_active_record.date_checksum = 0;
    highscore_active_record.year_offset = 0;
    highscore_active_record.month = 0;
    highscore_active_record.day = 0;
    highscore_active_record.flags = 0;
    highscore_active_record.random_tag = crt_rand() & 0x0fee050f;

    terrain_generate_random();
}

}
