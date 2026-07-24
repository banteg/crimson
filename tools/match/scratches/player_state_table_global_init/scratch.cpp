typedef struct IDirectSoundBuffer *LPDIRECTSOUNDBUFFER;

#include "crimsonland_types.h"

struct player_vec2_t {
    float x;
    float y;

    player_vec2_t(float x_value, float y_value)
        : x(x_value), y(y_value) {}
};

struct player_state_native_t : player_state_t {
    void construct_entity(void)
    {
        entity_reserved_74 = 0;
        entity_phase_seed = 0;
        entity_hit_flash_timer = 0.0f;
        entity_active = 0;
        entity_ai_mode = 0;
        entity_state_flag = 0;
        move_phase = 0.0f;
        plaguebearer_active = 0;
        entity_collision_timer = 0.0f;
        entity_link_index = -1;
    }
};

extern "C" player_state_native_t player_state_table[2];

extern "C" void player_state_table_global_init(void)
{
    int remaining = 2;
    player_state_native_t *entry = player_state_table;

    do {
        entry->construct_entity();

        entry->fire_bullets_timer = 0.0f;
        entry->low_health_timer = 0.0f;
        entry->man_bomb_timer = 0.0f;
        entry->living_fortress_timer = 0.0f;
        entry->fire_cough_timer = 0.0f;
        *(player_vec2_t *)&entry->move_target_x =
            player_vec2_t(-1.0f, -1.0f);
        entry->evil_eyes_target_creature = -1;
        entry->auto_target = 0;
        entry->player_reserved_98 = 0.0f;
        entry->hot_tempered_timer = 0.0f;
        entry->reload_active = 0;
        entry->shield_timer = 0.0f;
        entry->turn_speed = 0.0f;
        entry->experience = 0;
        entry->level = 1;
        entry->shot_cooldown = 0.0f;
        entry->reset_reserved_zero = 0;
        entry->clip_size = 30.0f;
        entry->muzzle_flash_alpha = 0.0f;
        ++entry;
    } while (--remaining != 0);
}
