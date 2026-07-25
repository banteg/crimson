#include "crimsonland_gameplay.h"

typedef union creature_spawn_locals_t {
    int zero_words[2];
    vec2f_t zero_velocity;
} creature_spawn_locals_t;

#define CREATURE_SPAWN_ELAPSED_SCALE 0.000010000001f

int creature_spawn(
    const vec2f_t *pos,
    const effect_color_t *tint,
    int type_id)
{
    int slot_id = creature_alloc_slot();
    creature_spawn_locals_t velocity_storage = {{0, 0}};

    creature_pool[slot_id].position = *pos;
    creature_pool[slot_id].type_id = type_id;
    creature_pool[slot_id].ai_mode = 0;
    creature_pool[slot_id].collision_flag = 0;
    creature_pool[slot_id].collision_timer = 0.0f;
    creature_pool[slot_id].active = 1;
    creature_pool[slot_id].force_target = 0;
    creature_pool[slot_id].state_flag = 1;
    creature_pool[slot_id].lifecycle_stage = 16.0f;
    creature_pool[slot_id].vel_x = velocity_storage.zero_velocity.x;
    creature_pool[slot_id].vel_y = velocity_storage.zero_velocity.y;
    creature_pool[slot_id].health = (float)survival_elapsed_ms * 0.0001f + 10.0f;
    creature_pool[slot_id].heading = (float)(crt_rand() % 314) * 0.01f;
    creature_pool[slot_id].move_speed = (float)survival_elapsed_ms * CREATURE_SPAWN_ELAPSED_SCALE + 2.5f;
    {
        int reward_roll = crt_rand();
        creature_pool[slot_id].attack_cooldown = 0.0f;
        creature_pool[slot_id].reward_value = (float)(reward_roll % 30 + 140);
    }
    creature_pool[slot_id].color = *tint;
    creature_pool[slot_id].contact_damage = 4.0f;
    creature_pool[slot_id].max_health = creature_pool[slot_id].health;
    creature_pool[slot_id].size = (float)survival_elapsed_ms * CREATURE_SPAWN_ELAPSED_SCALE + 47.0f;

    return slot_id;
}
