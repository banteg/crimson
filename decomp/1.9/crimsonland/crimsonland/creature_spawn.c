#include "crimsonland_gameplay.h"

typedef union creature_spawn_locals_t {
    int zero_words[2];
    vec2f_t zero_velocity;
} creature_spawn_locals_t;

#define CREATURE_SPAWN_ELAPSED_SCALE 0.000010000001f

static __inline void initialize_spawn(creature_t *creature, const vec2f_t *pos, int type_id)
{
    float health;
    creature_spawn_locals_t velocity_storage = {{0, 0}};
    creature->position = *pos;
    creature->type_id = type_id;
    creature->ai_mode = 0;
    creature->collision_flag = 0;
    creature->collision_timer = 0.0f;
    creature->active = 1;
    creature->force_target = 0;
    creature->state_flag = 1;
    creature->lifecycle_stage = 16.0f;
    health = (float)survival_elapsed_ms * 0.000100000005f + 10.0f;
    creature->vel_x = velocity_storage.zero_velocity.x;
    creature->vel_y = velocity_storage.zero_velocity.y;
    creature->health = health;
}

static __inline void finish_spawn(creature_t *creature, const effect_color_t *tint)
{
    creature->color = *tint;
    creature->size = (float)survival_elapsed_ms * CREATURE_SPAWN_ELAPSED_SCALE + 47.0f;
    creature->contact_damage = 4.0f;
    creature->max_health = creature->health;
}

int creature_spawn(
    const vec2f_t *pos,
    const effect_color_t *tint,
    int type_id)
{
    int slot_id = creature_alloc_slot();

    initialize_spawn(&creature_pool[slot_id], pos, type_id);
    creature_pool[slot_id].heading = (float)(crt_rand() % 314) * 0.01f;
    creature_pool[slot_id].move_speed = (float)survival_elapsed_ms * CREATURE_SPAWN_ELAPSED_SCALE + 2.5f;
    {
        int reward_roll = crt_rand();
        creature_pool[slot_id].attack_cooldown = 0.0f;
        creature_pool[slot_id].reward_value = (float)(reward_roll % 30 + 140);
    }
    finish_spawn(&creature_pool[slot_id], tint);

    return slot_id;
}
