#define creature_spawn_tinted creature_spawn_tinted_pointer_abi
#include "crimsonland_gameplay.h"
#undef creature_spawn_tinted

typedef union creature_spawn_tinted_locals_t {
    int zero_words[2];
    vec2f_t zero_velocity;
} creature_spawn_tinted_locals_t;

extern "C" int creature_spawn_tinted(
    const vec2f_t *pos,
    const effect_color_t *color,
    int type_id)
{
    int slot_id = creature_alloc_slot();
    creature_spawn_tinted_locals_t velocity_storage = {{0, 0}};

    // The copy through its own pointer gives the position its own alias
    // class, so C2 9044 orders the following field stores after it.
    vec2f_t *dst_pos = &creature_pool[slot_id].position;
    *dst_pos = *pos;
    creature_pool[slot_id].active = 1;
    creature_pool[slot_id].state_flag = 1;
    // Code-generation guard: 1.9.8 stores vel_x next to vel_y, which 1.9.93's
    // C2 (8966) only produces from this order; no shared order matches both.
#if CL_BUILD != 10908
    creature_pool[slot_id].vel_x = velocity_storage.zero_velocity.x;
#endif
    creature_pool[slot_id].ai_mode = 2;
    creature_pool[slot_id].plague_infected = 0;
    creature_pool[slot_id].dot_tick_timer = 0.0f;
    creature_pool[slot_id].type_id = type_id;
    creature_pool[slot_id].force_target = 0;
    creature_pool[slot_id].death_timer = 16.0f;
    creature_pool[slot_id].health = 1.0f;
#if CL_BUILD == 10908
    creature_pool[slot_id].vel_x = velocity_storage.zero_velocity.x;
#endif
    creature_pool[slot_id].vel_y = velocity_storage.zero_velocity.y;
    {
        int heading_roll = crt_rand();
        creature_pool[slot_id].move_speed = 1.7f;
        creature_pool[slot_id].reward_value = 1.0f;
        creature_pool[slot_id].attack_cooldown = 0.0f;
        creature_pool[slot_id].heading = (float)(heading_roll % 314) * 0.01f;
    }
    creature_pool[slot_id].color = *color;
    {
        int size_roll = crt_rand();
        int size_offset = size_roll % 20;
        float size;
        creature_pool[slot_id].contact_damage = 100.0f;
        creature_pool[slot_id].max_health = creature_pool[slot_id].health;
        size = (float)size_offset + 47.0f;
        creature_pool[slot_id].size = size;

        if (type_id == 3 || type_id == 4) {
            // Code-generation guard: 9044 forward-substitutes the single-use
            // local past the flags update; 8966 needs it to keep native order.
#if CL_BUILD == 10908
            creature_pool[slot_id].flags |= 0x80;
            creature_pool[slot_id].move_speed *= 1.2f;
#else
            float move_speed = creature_pool[slot_id].move_speed * 1.2f;
            creature_pool[slot_id].flags |= 0x80;
            creature_pool[slot_id].move_speed = move_speed;
#endif
            creature_pool[slot_id].size = size * 0.8f;
        }
    }

    return slot_id;
}
