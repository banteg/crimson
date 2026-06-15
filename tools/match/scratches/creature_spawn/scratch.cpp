#include "crimsonland_gameplay.h"

typedef union creature_spawn_locals_t {
    int i[2];
    float f[2];
} creature_spawn_locals_t;

extern "C" int creature_spawn(float *pos, float *tint_rgba, int type_id)
{
    creature_spawn_locals_t locals;
    int slot_id = creature_alloc_slot();
    locals.i[0] = 0;
    locals.i[1] = 0;

    creature_pool[slot_id].pos_x = pos[0];
    creature_pool[slot_id].pos_y = pos[1];
    creature_pool[slot_id].type_id = type_id;
    creature_pool[slot_id].ai_mode = 0;
    creature_pool[slot_id].collision_flag = 0;
    creature_pool[slot_id].collision_timer = 0.0f;
    creature_pool[slot_id].active = 1;
    creature_pool[slot_id].force_target = 0;
    creature_pool[slot_id].state_flag = 1;
    creature_pool[slot_id].hitbox_size = 16.0f;
    creature_pool[slot_id].vel_x = locals.f[0];
    creature_pool[slot_id].vel_y = locals.f[1];
    creature_pool[slot_id].health = (float)survival_elapsed_ms * 0.0001f + 10.0f;
    creature_pool[slot_id].heading = (float)(crt_rand() % 314) * 0.01f;
    creature_pool[slot_id].move_speed = (float)survival_elapsed_ms * 0.00001f + 2.5f;
    int reward_roll = crt_rand();
    creature_pool[slot_id].attack_cooldown = 0.0f;
    creature_pool[slot_id].reward_value = (float)(reward_roll % 30 + 140);
    float *tint = &creature_pool[slot_id].tint_r;
    tint[0] = tint_rgba[0];
    tint[1] = tint_rgba[1];
    tint[2] = tint_rgba[2];
    tint[3] = tint_rgba[3];
    creature_pool[slot_id].contact_damage = 4.0f;
    creature_pool[slot_id].max_health = creature_pool[slot_id].health;
    creature_pool[slot_id].size = (float)survival_elapsed_ms * 0.00001f + 47.0f;

    return slot_id;
}
