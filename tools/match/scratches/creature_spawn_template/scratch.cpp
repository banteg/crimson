#include <math.h>
#include "crimsonland_gameplay.h"

typedef union creature_spawn_template_locals_t {
    int i[15];
    float f[15];
} creature_spawn_template_locals_t;

#define slot_10_i locals.i[0]
#define slot_14_i locals.i[1]
#define slot_18_i locals.i[2]
#define tint_r_bits locals.i[10]
#define tint_g_bits locals.i[11]
#define tint_b_bits locals.i[12]
#define tint_a_bits locals.i[13]

#define STORE_FLOAT_BITS(field, slot, bits) \
    do {                                    \
        (slot) = (bits);                    \
        *(int *)&(field) = (slot);          \
    } while (0)

#define APPLY_UNHANDLED_TEMPLATE_FALLBACK()                                      \
    do {                                                                         \
        creature->type_id = CREATURE_TYPE_ALIEN;                                 \
        creature->health = 20.0f;                                                \
        console_printf(&console_log_queue, s_Unhandled_creatureType__00477758);  \
    } while (0)

#define INIT_GRID_ROOT(creature_type, root_ai_mode, red, green, blue, health_value, speed_value, size_value) \
    do {                                                                                                    \
        creature->type_id = (creature_type);                                                                \
        creature->pos_x = *pos;                                                                             \
        creature->pos_y = pos[1];                                                                           \
        creature->ai_mode = (root_ai_mode);                                                                 \
        creature->tint_r = (red);                                                                           \
        creature->tint_g = (green);                                                                         \
        creature->health = (health_value);                                                                  \
        creature->move_speed = (speed_value);                                                               \
        creature->tint_b = (blue);                                                                          \
        creature->reward_value = 600.0f;                                                                    \
        creature->size = (size_value);                                                                      \
        creature->tint_a = 1.0f;                                                                            \
        creature->contact_damage = 40.0f;                                                                   \
        creature->pos_x = *pos;                                                                             \
        creature->pos_y = pos[1];                                                                           \
        creature->max_health = (health_value);                                                              \
    } while (0)

#define INIT_GRID_CHILD(child_ai_mode, child_type, child_health, red, green, blue, child_speed, alpha, child_size, damage) \
    do {                                                                                                                   \
        child_slot_idx = creature_alloc_slot();                                                                            \
        creature = &creature_pool[child_slot_idx];                                                                         \
        creature->target_offset_y = (float)(int)pos;                                                                       \
        creature->ai_mode = (child_ai_mode);                                                                               \
        creature->heading = 0.0f;                                                                                          \
        creature->anim_phase = 0.0f;                                                                                       \
        creature->link_index = root_slot_idx;                                                                              \
        creature->target_offset_x = (float)slot_10_i;                                                                      \
        creature->vel_x = 0.0f;                                                                                            \
        creature->pos_x = *origin_pos_ptr + creature->target_offset_x;                                                     \
        creature->vel_y = 0.0f;                                                                                            \
        creature->pos_y = creature->target_offset_y + origin_pos_ptr[1];                                                   \
        creature->health = (child_health);                                                                                 \
        creature->max_health = (child_health);                                                                             \
        creature->tint_r = (red);                                                                                          \
        pos = pos + 0x10;                                                                                                  \
        creature->tint_g = (green);                                                                                        \
        creature->collision_flag = 0;                                                                                      \
        creature->tint_b = (blue);                                                                                         \
        creature->collision_timer = 0.0f;                                                                                  \
        creature->active = 1;                                                                                              \
        creature->state_flag = 1;                                                                                          \
        creature->hitbox_size = 16.0f;                                                                                     \
        creature->attack_cooldown = 0.0f;                                                                                  \
        creature->type_id = (child_type);                                                                                  \
        creature->move_speed = (child_speed);                                                                              \
        creature->reward_value = 60.0f;                                                                                    \
        creature->tint_a = (alpha);                                                                                        \
        creature->size = (child_size);                                                                                     \
        creature->contact_damage = (damage);                                                                               \
    } while (0)

#define SPAWN_GRID(child_ai_mode, child_type, child_health, red, green, blue, child_speed, alpha, child_size, damage) \
    do {                                                                                                             \
        slot_10_i = 0;                                                                                               \
        do {                                                                                                         \
            pos = (float *)0x80;                                                                                     \
            do {                                                                                                     \
                INIT_GRID_CHILD((child_ai_mode), (child_type), (child_health), (red), (green), (blue),               \
                                (child_speed), (alpha), (child_size), (damage));                                     \
            } while ((int)pos < 0x101);                                                                              \
            slot_10_i = slot_10_i + -0x40;                                                                           \
        } while (-0x240 < slot_10_i);                                                                                \
    } while (0)

extern "C" void *creature_spawn_template(int template_id, float *pos, float heading)
{
    creature_spawn_template_locals_t locals;
    float *origin_pos_ptr;
    int root_slot_idx;
    int child_slot_idx;
    int random_heading_roll;
    int ring_member_idx;
    int chain_link_idx;
    creature_t *creature;

    root_slot_idx = creature_alloc_slot();
    if (heading == -100.0f) {
        random_heading_roll = crt_rand();
        heading = (float)(random_heading_roll % 0x274) * 0.01f;
    }

    creature = &creature_pool[root_slot_idx];
    slot_18_i = root_slot_idx * sizeof(creature_t);
    origin_pos_ptr = pos;
    slot_10_i = 0;
    slot_14_i = 0;

    creature->ai_mode = CREATURE_AI_ORBIT_PLAYER;
    creature->pos_x = *pos;
    creature->vel_x = 0.0f;
    creature->pos_y = pos[1];
    creature->collision_flag = 0;
    creature->collision_timer = 0.0f;
    creature->active = 1;
    *(unsigned char *)&creature->force_target = 0;
    creature->state_flag = 1;
    creature->hitbox_size = 16.0f;
    creature->vel_y = 0.0f;
    random_heading_roll = crt_rand();
    creature->attack_cooldown = 0.0f;
    creature->heading = (float)(random_heading_roll % 0x13a) * 0.01f;

    if (template_id == SPAWN_ID_FORMATION_RING_ALIEN_8_12) {
        STORE_FLOAT_BITS(creature->tint_r, tint_r_bits, 0x3f266666);
        STORE_FLOAT_BITS(creature->tint_g, tint_g_bits, 0x3f59999a);
        STORE_FLOAT_BITS(creature->tint_b, tint_b_bits, 0x3f7851ec);
        STORE_FLOAT_BITS(creature->tint_a, tint_a_bits, 0x3f800000);
        creature->type_id = CREATURE_TYPE_ALIEN;
        creature->health = 200.0f;
        creature->move_speed = 2.2f;
        creature->reward_value = 600.0f;
        creature->size = 55.0f;
        creature->contact_damage = 14.0f;
        creature->max_health = 200.0f;

        ring_member_idx = 0;
        slot_18_i = 0;
        slot_14_i = 0;
        tint_r_bits = 0x3ea3d70b;
        tint_g_bits = 0x3f16872c;
        tint_b_bits = 0x3eda1cac;
        tint_a_bits = 0x3f800000;
        do {
            child_slot_idx = creature_alloc_slot();
            float angle = (float)ring_member_idx * 0.78539819f;
            creature = &creature_pool[child_slot_idx];
            creature->ai_mode = CREATURE_AI_FOLLOW_LINK;
            creature->link_index = root_slot_idx;
            creature->target_offset_x = (float)cos(angle) * 100.0f;
            creature->target_offset_y = (float)sin(angle) * 100.0f;
            creature->pos_x = *origin_pos_ptr;
            creature->pos_y = origin_pos_ptr[1];
            creature->vel_x = 0.0f;
            creature->vel_y = 0.0f;
            creature->collision_flag = 0;
            *(int *)&creature->tint_r = tint_r_bits;
            creature->health = 40.0f;
            creature->max_health = 40.0f;
            *(int *)&creature->tint_g = tint_g_bits;
            ring_member_idx = ring_member_idx + 1;
            *(int *)&creature->tint_b = tint_b_bits;
            creature->collision_timer = 0.0f;
            creature->active = 1;
            creature->state_flag = 1;
            creature->hitbox_size = 16.0f;
            creature->attack_cooldown = 0.0f;
            creature->type_id = CREATURE_TYPE_ALIEN;
            creature->move_speed = 2.4f;
            creature->reward_value = 60.0f;
            *(int *)&creature->tint_a = tint_a_bits;
            creature->size = 50.0f;
            creature->contact_damage = 4.0f;
        } while (ring_member_idx < 8);
    } else if (template_id == SPAWN_ID_FORMATION_RING_ALIEN_5_19) {
        STORE_FLOAT_BITS(creature->tint_r, tint_r_bits, 0x3f733333);
        STORE_FLOAT_BITS(creature->tint_g, tint_g_bits, 0x3f0ccccd);
        STORE_FLOAT_BITS(creature->tint_b, tint_b_bits, 0x3ebd70a4);
        STORE_FLOAT_BITS(creature->tint_a, tint_a_bits, 0x3f800000);
        creature->type_id = CREATURE_TYPE_ALIEN;
        creature->health = 50.0f;
        creature->move_speed = 3.8f;
        creature->reward_value = 300.0f;
        creature->size = 55.0f;
        creature->contact_damage = 40.0f;
        creature->max_health = 50.0f;

        ring_member_idx = 0;
        slot_10_i = 0;
        slot_14_i = 0;
        tint_r_bits = 0x3f366666;
        tint_g_bits = 0x3ed33334;
        tint_b_bits = 0x3e8e147b;
        tint_a_bits = 0x3f19999a;
        do {
            child_slot_idx = creature_alloc_slot();
            float angle = (float)ring_member_idx * 1.2566371f;
            creature = &creature_pool[child_slot_idx];
            creature->ai_mode = CREATURE_AI_FOLLOW_LINK_TETHERED;
            creature->link_index = root_slot_idx;
            creature->target_offset_x = (float)cos(angle) * 110.0f;
            creature->target_offset_y = (float)sin(angle) * 110.0f;
            creature->pos_x = creature->target_offset_x + *origin_pos_ptr;
            creature->vel_x = 0.0f;
            creature->pos_y = creature->target_offset_y + origin_pos_ptr[1];
            creature->vel_y = 0.0f;
            creature->health = 220.0f;
            creature->max_health = 220.0f;
            *(int *)&creature->tint_r = tint_r_bits;
            ring_member_idx = ring_member_idx + 1;
            *(int *)&creature->tint_g = tint_g_bits;
            creature->collision_flag = 0;
            *(int *)&creature->tint_b = tint_b_bits;
            creature->collision_timer = 0.0f;
            creature->active = 1;
            creature->state_flag = 1;
            creature->hitbox_size = 16.0f;
            creature->attack_cooldown = 0.0f;
            creature->type_id = CREATURE_TYPE_ALIEN;
            creature->move_speed = 3.8f;
            creature->reward_value = 60.0f;
            *(int *)&creature->tint_a = tint_a_bits;
            creature->size = 50.0f;
            creature->contact_damage = 35.0f;
        } while (ring_member_idx < 5);
    } else {
        if (template_id == SPAWN_ID_FORMATION_CHAIN_LIZARD_4_11) {
            creature->type_id = CREATURE_TYPE_LIZARD;
            creature->pos_x = *pos;
            creature->pos_y = pos[1];
            creature->ai_mode = CREATURE_AI_ORBIT_PLAYER_TIGHT;
            creature->tint_r = 0.99f;
            creature->tint_g = 0.99f;
            creature->health = 1500.0f;
            creature->move_speed = 2.1f;
            creature->tint_b = 0.21f;
            creature->reward_value = 1000.0f;
            creature->size = 69.0f;
            creature->tint_a = 1.0f;
            creature->contact_damage = 150.0f;
            creature->max_health = 1500.0f;

            slot_10_i = 2;
            pos = (float *)0xffffff00;
            chain_link_idx = root_slot_idx;
            do {
                child_slot_idx = creature_alloc_slot();
                creature = &creature_pool[child_slot_idx];
                creature->target_offset_x = (float)(int)pos;
                creature->ai_mode = CREATURE_AI_FOLLOW_LINK;
                creature->link_index = chain_link_idx;
                creature->target_offset_y = -256.0f;
                float angle = (float)slot_10_i * 0.39269909f;
                creature->pos_x = (float)cos(angle) * 256.0f + *origin_pos_ptr;
                creature->vel_x = 0.0f;
                creature->tint_r = 0.6f;
                creature->pos_y = (float)sin(angle) * 256.0f + origin_pos_ptr[1];
                creature->tint_g = 0.6f;
                creature->vel_y = 0.0f;
                creature->tint_b = 0.31f;
                creature->health = 60.0f;
                creature->reward_value = 60.0f;
                creature->max_health = 60.0f;
                creature->tint_a = 1.0f;
                pos = pos + 0x10;
                slot_10_i = slot_10_i + 2;
                creature->collision_flag = 0;
                creature->collision_timer = 0.0f;
                creature->active = 1;
                creature->state_flag = 1;
                creature->hitbox_size = 16.0f;
                creature->attack_cooldown = 0.0f;
                creature->type_id = CREATURE_TYPE_LIZARD;
                creature->move_speed = 2.4f;
                creature->size = 50.0f;
                creature->contact_damage = 14.0f;
                chain_link_idx = child_slot_idx;
            } while ((int)pos < 0);
            creature_pool[root_slot_idx].link_index = child_slot_idx;
            APPLY_UNHANDLED_TEMPLATE_FALLBACK();
        } else {
            if (template_id != SPAWN_ID_FORMATION_CHAIN_ALIEN_10_13) {
                if (template_id == SPAWN_ID_FORMATION_GRID_ALIEN_GREEN_14) {
                    creature = &creature_pool[root_slot_idx];
                    INIT_GRID_ROOT(CREATURE_TYPE_ALIEN, CREATURE_AI_CHASE_PLAYER,
                                   0.7f, 0.8f, 0.31f, 1500.0f, 2.0f, 50.0f);
                    SPAWN_GRID(CREATURE_AI_FOLLOW_LINK_TETHERED, CREATURE_TYPE_ALIEN, 40.0f,
                               0.4f, 0.7f, 0.11f, 2.0f, 1.0f, 50.0f, 4.0f);
                } else if (template_id == SPAWN_ID_FORMATION_GRID_ALIEN_WHITE_15) {
                    creature = &creature_pool[root_slot_idx];
                    INIT_GRID_ROOT(CREATURE_TYPE_ALIEN, CREATURE_AI_CHASE_PLAYER,
                                   1.0f, 1.0f, 1.0f, 1500.0f, 2.0f, 60.0f);
                    SPAWN_GRID(CREATURE_AI_LINK_GUARD, CREATURE_TYPE_ALIEN, 40.0f,
                               0.4f, 0.7f, 0.11f, 2.0f, 1.0f, 50.0f, 4.0f);
                } else if (template_id == SPAWN_ID_FORMATION_GRID_SPIDER_SP1_WHITE_17) {
                    creature = &creature_pool[root_slot_idx];
                    INIT_GRID_ROOT(CREATURE_TYPE_SPIDER_SP1, CREATURE_AI_CHASE_PLAYER,
                                   1.0f, 1.0f, 1.0f, 1500.0f, 2.0f, 60.0f);
                    SPAWN_GRID(CREATURE_AI_LINK_GUARD, CREATURE_TYPE_SPIDER_SP1, 40.0f,
                               0.4f, 0.7f, 0.11f, 2.0f, 1.0f, 50.0f, 4.0f);
                } else if (template_id == SPAWN_ID_FORMATION_GRID_LIZARD_WHITE_16) {
                    creature = &creature_pool[root_slot_idx];
                    INIT_GRID_ROOT(CREATURE_TYPE_LIZARD, CREATURE_AI_CHASE_PLAYER,
                                   1.0f, 1.0f, 1.0f, 1500.0f, 2.0f, 64.0f);
                    SPAWN_GRID(CREATURE_AI_LINK_GUARD, CREATURE_TYPE_LIZARD, 40.0f,
                               0.4f, 0.7f, 0.11f, 2.0f, 1.0f, 60.0f, 4.0f);
                } else if (template_id == SPAWN_ID_FORMATION_GRID_ALIEN_BRONZE_18) {
                    creature = &creature_pool[root_slot_idx];
                    INIT_GRID_ROOT(CREATURE_TYPE_ALIEN, CREATURE_AI_CHASE_PLAYER,
                                   0.7f, 0.8f, 0.31f, 500.0f, 2.0f, 40.0f);
                    SPAWN_GRID(CREATURE_AI_FOLLOW_LINK, CREATURE_TYPE_ALIEN, 260.0f,
                               0.7125f, 0.41250002f, 0.2775f, 3.8f, 0.6f, 50.0f, 35.0f);
                }
            } else {
                creature->type_id = CREATURE_TYPE_ALIEN;
                slot_10_i = terrain_texture_height / 2;
                creature->ai_mode = CREATURE_AI_CHASE_PLAYER;
                creature->pos_x = -10.0f;
                creature->tint_r = 0.6f;
                creature->pos_y = (float)slot_10_i;
                creature->tint_g = 0.8f;
                creature->tint_b = 0.91f;
                creature->health = 200.0f;
                creature->move_speed = 2.0f;
                creature->reward_value = 600.0f;
                creature->tint_a = 1.0f;
                creature->size = 40.0f;
                creature->contact_damage = 20.0f;
                pos = (float *)0x2;
                creature->max_health = 200.0f;
                creature->pos_x = (float)cos(0.0f) * 256.0f + *origin_pos_ptr;
                creature->ai_mode = CREATURE_AI_ORBIT_LINK;
                creature->pos_y = (float)sin(0.0f) * 256.0f + origin_pos_ptr[1];
                chain_link_idx = root_slot_idx;
                do {
                    child_slot_idx = creature_alloc_slot();
                    float angle = (float)(int)pos * 0.34906587f;
                    creature = &creature_pool[child_slot_idx];
                    creature->ai_mode = CREATURE_AI_ORBIT_LINK;
                    creature->link_index = chain_link_idx;
                    creature->orbit_angle = 3.1415927f;
                    creature->orbit_radius.raw_u32 = 0x41200000;
                    creature->pos_x = (float)cos(angle) * 256.0f + *origin_pos_ptr;
                    creature->vel_x = 0.0f;
                    creature->health = 60.0f;
                    creature->pos_y = (float)sin(angle) * 256.0f + origin_pos_ptr[1];
                    creature->vel_y = 0.0f;
                    creature->reward_value = 60.0f;
                    creature->max_health = 60.0f;
                    creature->tint_r = 0.4f;
                    pos = (float *)((int)pos + 2);
                    creature->tint_g = 0.7f;
                    creature->collision_flag = 0;
                    creature->tint_b = 0.11f;
                    creature->collision_timer = 0.0f;
                    creature->active = 1;
                    creature->tint_a = 1.0f;
                    creature->state_flag = 1;
                    creature->hitbox_size = 16.0f;
                    creature->attack_cooldown = 0.0f;
                    creature->type_id = CREATURE_TYPE_ALIEN;
                    creature->move_speed = 2.0f;
                    creature->size = 50.0f;
                    creature->contact_damage = 4.0f;
                    chain_link_idx = child_slot_idx;
                } while ((int)pos < 0x16);
                creature_pool[root_slot_idx].link_index = child_slot_idx;
                APPLY_UNHANDLED_TEMPLATE_FALLBACK();
            }
        }
    }

    if (!demo_mode_active
        && creature->pos_x > 0.0f
        && (float)terrain_texture_width > creature->pos_x
        && creature->pos_y > 0.0f
        && (float)terrain_texture_height > creature->pos_y) {
        effect_spawn_burst(&creature->pos_x, 8);
    }

    creature->max_health = creature->health;
    int flags = creature->flags;
    if ((flags & CREATURE_FLAG_RANGED_ATTACK_SHOCK) == 0
        && creature->type_id == CREATURE_TYPE_SPIDER_SP1
        && (flags & CREATURE_FLAG_AI7_LINK_TIMER) == 0) {
        flags = flags | CREATURE_FLAG_AI7_LINK_TIMER;
        creature->flags = flags;
        creature->link_index = 0;
        creature->move_speed = creature->move_speed * 1.2f;
    }

    if (template_id == SPAWN_ID_SPIDER_SP1_AI7_TIMER_38 && config_blob.hardcore) {
        creature->move_speed = creature->move_speed * 0.7f;
    }

    creature->heading = heading;
    if (config_blob.hardcore) {
        quest_fail_retry_count = 0;
        creature->move_speed = creature->move_speed * 1.05f;
        creature->contact_damage = creature->contact_damage * 1.4f;
        creature->health = creature->health * 1.2f;
        if ((creature->flags & CREATURE_FLAG_ANIM_PING_PONG) != 0) {
            int slot_index = creature->link_index;
            creature_spawn_slot_table[slot_index].interval_s =
                creature_spawn_slot_table[slot_index].interval_s - 0.2f;
            if (creature_spawn_slot_table[slot_index].interval_s < 0.1f) {
                creature_spawn_slot_table[slot_index].interval_s = 0.1f;
            }
        }
    } else {
        if ((creature->flags & CREATURE_FLAG_ANIM_PING_PONG) != 0) {
            creature_spawn_slot_table[creature->link_index].interval_s =
                creature_spawn_slot_table[creature->link_index].interval_s + 0.2f;
        }
        if (quest_fail_retry_count > 0) {
            switch (quest_fail_retry_count) {
            case 1:
                creature->reward_value = creature->reward_value * 0.9f;
                creature->move_speed = creature->move_speed * 0.95f;
                creature->contact_damage = creature->contact_damage * 0.95f;
                creature->health = creature->health * 0.95f;
                break;
            case 2:
                creature->reward_value = creature->reward_value * 0.85f;
                creature->move_speed = creature->move_speed * 0.9f;
                creature->contact_damage = creature->contact_damage * 0.9f;
                creature->health = creature->health * 0.9f;
                break;
            case 3:
                creature->reward_value = creature->reward_value * 0.85f;
                creature->move_speed = creature->move_speed * 0.8f;
                creature->contact_damage = creature->contact_damage * 0.8f;
                creature->health = creature->health * 0.8f;
                break;
            case 4:
                creature->reward_value = creature->reward_value * 0.8f;
                creature->move_speed = creature->move_speed * 0.7f;
                creature->contact_damage = creature->contact_damage * 0.7f;
                creature->health = creature->health * 0.7f;
                break;
            default:
                creature->reward_value = creature->reward_value * 0.8f;
                creature->move_speed = creature->move_speed * 0.6f;
                creature->contact_damage = creature->contact_damage * 0.5f;
                creature->health = creature->health * 0.5f;
                break;
            }
            if ((creature->flags & CREATURE_FLAG_ANIM_PING_PONG) != 0) {
                float retry_interval = (float)quest_fail_retry_count * 0.35f;
                if (retry_interval > 3.0f) {
                    retry_interval = 3.0f;
                }
                creature_spawn_slot_table[creature->link_index].interval_s =
                    creature_spawn_slot_table[creature->link_index].interval_s + retry_interval;
            }
        }
    }

    return creature;
}

#undef STORE_FLOAT_BITS
#undef APPLY_UNHANDLED_TEMPLATE_FALLBACK
#undef INIT_GRID_ROOT
#undef INIT_GRID_CHILD
#undef SPAWN_GRID
#undef slot_10_i
#undef slot_14_i
#undef slot_18_i
#undef tint_r_bits
#undef tint_g_bits
#undef tint_b_bits
#undef tint_a_bits
