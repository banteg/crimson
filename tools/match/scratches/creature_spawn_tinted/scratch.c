#define creature_spawn_tinted creature_spawn_tinted_pointer_abi
#include "crimsonland_gameplay.h"
#undef creature_spawn_tinted

typedef union creature_spawn_tinted_locals_t {
    int i[2];
    float f[2];
} creature_spawn_tinted_locals_t;

typedef struct creature_spawn_tinted_color_t {
    float r;
    float g;
    float b;
    float a;
} creature_spawn_tinted_color_t;

int creature_spawn_tinted(
    const vec2f_t *pos,
    const effect_color_t *color,
    int type_id)
{
    int slot_id = creature_alloc_slot();
    creature_spawn_tinted_locals_t locals = {{0, 0}};

    creature_pool[slot_id].pos_x = pos->x;
    creature_pool[slot_id].pos_y = pos->y;
    creature_pool[slot_id].active = 1;
    creature_pool[slot_id].state_flag = 1;
    creature_pool[slot_id].vel_x = locals.f[0];
    creature_pool[slot_id].ai_mode = 2;
    creature_pool[slot_id].collision_flag = 0;
    creature_pool[slot_id].collision_timer = 0.0f;
    creature_pool[slot_id].type_id = type_id;
    creature_pool[slot_id].force_target = 0;
    creature_pool[slot_id].lifecycle_stage = 16.0f;
    creature_pool[slot_id].health = 1.0f;
    creature_pool[slot_id].vel_y = locals.f[1];
    {
        int heading_roll = crt_rand();
        creature_pool[slot_id].move_speed = 1.7f;
        creature_pool[slot_id].reward_value = 1.0f;
        creature_pool[slot_id].attack_cooldown = 0.0f;
        creature_pool[slot_id].heading = (float)(heading_roll % 314) * 0.01f;
    }
    *(creature_spawn_tinted_color_t *)&creature_pool[slot_id].tint_r =
        *(const creature_spawn_tinted_color_t *)color;
    {
        int size_roll = crt_rand();
        int size_offset = size_roll % 20;
        float size;
        creature_pool[slot_id].contact_damage = 100.0f;
        creature_pool[slot_id].max_health = creature_pool[slot_id].health;
        size = (float)size_offset + 47.0f;
        creature_pool[slot_id].size = size;

        if (type_id == 3 || type_id == 4) {
            float move_speed = creature_pool[slot_id].move_speed * 1.2f;
            creature_pool[slot_id].flags |= 0x80;
            creature_pool[slot_id].move_speed = move_speed;
            creature_pool[slot_id].size = size * 0.8f;
        }
    }

    return slot_id;
}
