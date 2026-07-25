#include <math.h>
#include "crimsonland_gameplay.h"

struct creature_tint_t {
    float r;
    float g;
    float b;
    float a;

    void set(float red, float green, float blue, float alpha)
    {
        r = red;
        g = green;
        b = blue;
        a = alpha;
    }
};

struct creature_spawn_vec2_t {
    float x;
    float y;

    void set(float x_value, float y_value)
    {
        x = x_value;
        y = y_value;
    }
};

struct creature_spawn_root_vec2_t {
    float x;
    float y;

    creature_spawn_root_vec2_t(float x_value, float y_value)
        : x(x_value), y(y_value)
    {
    }
};

typedef union creature_spawn_tint_scratch_t {
    creature_tint_t tint;
    creature_spawn_vec2_t orbit_direction;
} creature_spawn_tint_scratch_t;

typedef struct creature_spawn_template_named_locals_t {
    int formation_offset;
    creature_spawn_vec2_t zero_velocity;
    creature_spawn_vec2_t chain_position;
    float scaled_orbit_x;
    int scratch_tail;
    creature_spawn_tint_scratch_t tint_scratch;
    creature_tint_t child_tint;
} creature_spawn_template_named_locals_t;

typedef creature_spawn_template_named_locals_t creature_spawn_template_locals_t;

#define tint locals.tint_scratch.tint
#define child_tint locals.child_tint
#define zero_velocity locals.zero_velocity
#define chain_position locals.chain_position
#define lizard_chain_position zero_velocity
#define lizard_chain_zero_velocity chain_position
#define scaled_orbit_x locals.scaled_orbit_x
#define orbit_direction locals.tint_scratch.orbit_direction

#define APPLY_UNHANDLED_TEMPLATE_FALLBACK()                                      \
    do {                                                                         \
        creature->type_id = CREATURE_TYPE_ALIEN;                                 \
        creature->health = 20.0f;                                                \
        console_printf(&console_log_queue, s_unhandled_creature_type);          \
    } while (0)

#define INIT_GRID_ROOT(creature_type, root_ai_mode, red, green, blue, health_value, speed_value, size_value) \
    do {                                                                                                    \
        creature->type_id = (creature_type);                                                                \
        creature->position.x = pos->x;                                                                           \
        creature->position.y = pos->y;                                                                           \
        creature->ai_mode = (root_ai_mode);                                                                 \
        child_tint.set((red), (green), (blue), 1.0f);                                                       \
        creature->health = (health_value);                                                                  \
        *(creature_tint_t *)&creature->color = child_tint;                                                 \
        creature->move_speed = (speed_value);                                                               \
        creature->reward_value = 600.0f;                                                                    \
        creature->size = (size_value);                                                                      \
        creature->contact_damage = 40.0f;                                                                   \
        creature->position.x = pos->x;                                                                           \
        creature->position.y = pos->y;                                                                           \
        creature->max_health = (health_value);                                                              \
    } while (0)

#define INIT_GRID_CHILD(child_ai_mode, child_type, child_health, red, green, blue, child_speed, alpha, child_size, damage) \
    do {                                                                                                                   \
        child_slot_idx = creature_alloc_slot();                                                                            \
        creature = &creature_pool[child_slot_idx];                                                                         \
        creature->target_offset.y = (float)grid_vertical_offset;                                                           \
        creature->ai_mode = (child_ai_mode);                                                                               \
        creature->heading = 0.0f;                                                                                          \
        creature->anim_phase = 0.0f;                                                                                       \
        creature->link_index = root_slot_idx;                                                                              \
        creature->target_offset.x = (float)locals.formation_offset;                                                        \
        chain_position.set(pos->x + creature->target_offset.x, creature->target_offset.y + pos->y);                       \
        *(creature_spawn_vec2_t *)&creature->position = chain_position;                                                    \
        *(creature_spawn_vec2_t *)&creature->velocity = zero_velocity;                                                     \
        creature->health = (child_health);                                                                                 \
        *(creature_tint_t *)&creature->color = child_tint;                                                                 \
        creature->max_health = (child_health);                                                                             \
        grid_vertical_offset = grid_vertical_offset + 0x40;                                                                \
        creature->collision_flag = 0;                                                                                      \
        creature->collision_timer = 0.0f;                                                                                  \
        creature->active = 1;                                                                                              \
        creature->state_flag = 1;                                                                                          \
        creature->lifecycle_stage = 16.0f;                                                                                     \
        creature->attack_cooldown = 0.0f;                                                                                  \
        creature->type_id = (child_type);                                                                                  \
        creature->move_speed = (child_speed);                                                                              \
        creature->reward_value = 60.0f;                                                                                    \
        creature->size = (child_size);                                                                                     \
        creature->contact_damage = (damage);                                                                               \
    } while (0)

#define SPAWN_GRID(child_ai_mode, child_type, child_health, red, green, blue, child_speed, alpha, child_size, damage) \
    do {                                                                                                             \
        zero_velocity.set(0.0f, 0.0f);                                                                              \
        child_tint.set((red), (green), (blue), (alpha));                                                             \
        locals.formation_offset = 0;                                                                                 \
        do {                                                                                                         \
            grid_vertical_offset = 0x80;                                                                             \
            do {                                                                                                     \
                INIT_GRID_CHILD((child_ai_mode), (child_type), (child_health), (red), (green), (blue),               \
                                (child_speed), (alpha), (child_size), (damage));                                     \
            } while (grid_vertical_offset <= 0x100);                                                                 \
            locals.formation_offset = locals.formation_offset + -0x40;                                               \
        } while (-0x240 < locals.formation_offset);                                                                  \
    } while (0)

#define SET_ROOT_STATS(creature_type, health_value, speed_value, reward, red, green, blue, alpha, size_value, damage) \
    do {                                                                                                             \
        creature->type_id = (creature_type);                                                                         \
        creature->health = (health_value);                                                                           \
        creature->move_speed = (speed_value);                                                                        \
        creature->reward_value = (reward);                                                                           \
        creature->color.r = (red);                                                                                    \
        creature->color.g = (green);                                                                                  \
        creature->color.b = (blue);                                                                                   \
        creature->color.a = (alpha);                                                                                  \
        creature->size = (size_value);                                                                               \
        creature->contact_damage = (damage);                                                                         \
    } while (0)

#define SET_ROOT_STATS_WITH_TINT(creature_type, health_value, speed_value, reward, red, green, blue, alpha, size_value, damage) \
    do {                                                                                                                       \
        creature->type_id = (creature_type);                                                                                   \
        creature->health = (health_value);                                                                                     \
        creature->move_speed = (speed_value);                                                                                  \
        creature->reward_value = (reward);                                                                                     \
        child_tint.set((red), (green), (blue), (alpha));                                                                       \
        *(creature_tint_t *)&creature->color = child_tint;                                                                     \
        creature->size = (size_value);                                                                                         \
        creature->contact_damage = (damage);                                                                                   \
    } while (0)

#define INIT_ALIEN_SPAWNER(timer, limit_value, interval, child_template, size_value, health_value, speed_value, reward, red, green, blue) \
    do {                                                                                                                               \
        creature->type_id = CREATURE_TYPE_ALIEN;                                                                                       \
        creature->flags = CREATURE_FLAG_ANIM_PING_PONG;                                                                                \
        child_slot_idx = creature_spawn_slot_alloc();                                                                                  \
        creature->link_index = child_slot_idx;                                                                                         \
        creature_spawn_slot_t *spawn_slot = &creature_spawn_slot_table[child_slot_idx];                                                \
        spawn_slot->timer_s = (timer);                                                                                                 \
        spawn_slot->count = 0;                                                                                                         \
        spawn_slot->limit = (limit_value);                                                                                             \
        spawn_slot->interval_s = (interval);                                                                                           \
        spawn_slot->template_id = (child_template);                                                                                    \
        spawn_slot->owner = creature;                                                                                                  \
        creature->size = (size_value);                                                                                                 \
        creature->health = (health_value);                                                                                             \
        creature->move_speed = (speed_value);                                                                                          \
        creature->reward_value = (reward);                                                                                             \
        creature->color.a = 1.0f;                                                                                                       \
        creature->color.r = (red);                                                                                                      \
        creature->color.g = (green);                                                                                                    \
        creature->color.b = (blue);                                                                                                     \
        creature->contact_damage = 0.0f;                                                                                               \
    } while (0)

#define RAND_FIELD(field, mod_value, scale, base)                \
    do {                                                        \
        random_heading_roll = crt_rand();                       \
        (field) = (float)(random_heading_roll % (mod_value)) * (scale) + (base); \
    } while (0)

#define RAND_FIELD_INT_BASE(field, mod_value, base)       \
    do {                                                  \
        random_heading_roll = crt_rand();                 \
        (field) = (float)(random_heading_roll % (mod_value) + (base)); \
    } while (0)

#define CLAMP_TINT_COMPONENT(field) \
    do {                            \
        if ((field) < 0.0f) {       \
            (field) = 0.0f;         \
        } else if ((field) > 1.0f) { \
            (field) = 1.0f;         \
        }                           \
    } while (0)

extern "C" creature_t *creature_spawn_template(
    int template_id,
    const vec2f_t *pos,
    float heading)
{
    creature_spawn_template_locals_t locals;
    int root_slot_idx;
    int child_slot_idx;
    int random_heading_roll;
    int ring_member_idx;
    int chain_link_idx;
    int grid_vertical_offset;
    creature_t *creature;

    root_slot_idx = creature_alloc_slot();
    if (heading == -100.0f) {
        random_heading_roll = crt_rand();
        heading = (float)(random_heading_roll % 0x274) * 0.01f;
    }

    creature = &creature_pool[root_slot_idx];

    creature->ai_mode = CREATURE_AI_ORBIT_PLAYER;
    *(creature_spawn_vec2_t *)&creature->position = *(creature_spawn_vec2_t *)pos;
    *(creature_spawn_root_vec2_t *)&creature->velocity =
        creature_spawn_root_vec2_t(0.0f, 0.0f);
    creature->collision_flag = 0;
    creature->collision_timer = 0.0f;
    creature->active = 1;
    creature->force_target = 0;
    creature->state_flag = 1;
    creature->lifecycle_stage = 16.0f;
    random_heading_roll = crt_rand();
    creature->attack_cooldown = 0.0f;
    creature->heading = (float)(random_heading_roll % 0x13a) * 0.01f;

    if (template_id == SPAWN_ID_FORMATION_RING_ALIEN_8_12) {
        tint.r = 0.65f;
        tint.g = 0.85f;
        tint.b = 0.97f;
        tint.a = 1.0f;
        creature->type_id = CREATURE_TYPE_ALIEN;
        creature->health = 200.0f;
        *(creature_tint_t *)&creature->color = tint;
        creature->move_speed = 2.2f;
        creature->reward_value = 600.0f;
        creature->size = 55.0f;
        creature->contact_damage = 14.0f;
        creature->max_health = 200.0f;

        creature_spawn_vec2_t child_velocity;
        ring_member_idx = 0;
        child_velocity.set(0.0f, 0.0f);
        tint.r = 0.32000002f;
        tint.g = 0.58800006f;
        tint.b = 0.426f;
        tint.a = 1.0f;
        do {
            child_slot_idx = creature_alloc_slot();
            creature = &creature_pool[child_slot_idx];
            float angle = (float)ring_member_idx * 0.78539819f;
            creature->ai_mode = CREATURE_AI_FOLLOW_LINK;
            creature->link_index = root_slot_idx;
            creature->target_offset.x = (float)cos(angle) * 100.0f;
            creature->target_offset.y = (float)sin(angle) * 100.0f;
            creature->position.x = pos->x;
            creature->position.y = pos->y;
            *(creature_spawn_vec2_t *)&creature->velocity = child_velocity;
            creature->collision_flag = 0;
            creature->health = 40.0f;
            *(creature_tint_t *)&creature->color = tint;
            creature->max_health = 40.0f;
            creature->collision_timer = 0.0f;
            creature->active = 1;
            creature->state_flag = 1;
            creature->lifecycle_stage = 16.0f;
            creature->attack_cooldown = 0.0f;
            creature->type_id = CREATURE_TYPE_ALIEN;
            creature->move_speed = 2.4f;
            creature->reward_value = 60.0f;
            creature->size = 50.0f;
            creature->contact_damage = 4.0f;
            ring_member_idx = ring_member_idx + 1;
        } while (ring_member_idx < 8);
    }

    if (template_id == SPAWN_ID_FORMATION_RING_ALIEN_5_19) {
        tint.set(0.95f, 0.55f, 0.37f, 1.0f);
        creature->type_id = CREATURE_TYPE_ALIEN;
        creature->health = 50.0f;
        *(creature_tint_t *)&creature->color = tint;
        creature->move_speed = 3.8f;
        creature->reward_value = 300.0f;
        creature->size = 55.0f;
        creature->contact_damage = 40.0f;
        creature->max_health = 50.0f;

        creature_spawn_vec2_t child_velocity;
        ring_member_idx = 0;
        child_velocity.set(0.0f, 0.0f);
        tint.set(0.7125f, 0.41250002f, 0.2775f, 0.6f);
        do {
            child_slot_idx = creature_alloc_slot();
            creature = &creature_pool[child_slot_idx];
            float angle = (float)ring_member_idx * 1.2566371f;
            creature->ai_mode = CREATURE_AI_FOLLOW_LINK_TETHERED;
            creature->link_index = root_slot_idx;
            creature->target_offset.x = (float)cos(angle) * 110.0f;
            creature->target_offset.y = (float)sin(angle) * 110.0f;
            chain_position.set(
                creature->target_offset.x + pos->x,
                creature->target_offset.y + pos->y);
            *(creature_spawn_vec2_t *)&creature->position = chain_position;
            *(creature_spawn_vec2_t *)&creature->velocity = child_velocity;
            creature->health = 220.0f;
            *(creature_tint_t *)&creature->color = tint;
            creature->max_health = 220.0f;
            creature->collision_flag = 0;
            creature->collision_timer = 0.0f;
            creature->active = 1;
            creature->state_flag = 1;
            creature->lifecycle_stage = 16.0f;
            creature->attack_cooldown = 0.0f;
            creature->type_id = CREATURE_TYPE_ALIEN;
            creature->move_speed = 3.8f;
            creature->reward_value = 60.0f;
            creature->size = 50.0f;
            creature->contact_damage = 35.0f;
            ring_member_idx = ring_member_idx + 1;
        } while (ring_member_idx < 5);
    }

    if (template_id == SPAWN_ID_FORMATION_CHAIN_LIZARD_4_11) {
            int chain_target_offset;
            creature->type_id = CREATURE_TYPE_LIZARD;
            creature->position.x = pos->x;
            creature->position.y = pos->y;
            creature->ai_mode = CREATURE_AI_ORBIT_PLAYER_TIGHT;
            tint.set(0.99f, 0.99f, 0.21f, 1.0f);
            creature->health = 1500.0f;
            creature->move_speed = 2.1f;
            creature->reward_value = 1000.0f;
            *(creature_tint_t *)&creature->color = tint;
            creature->size = 69.0f;
            creature->contact_damage = 150.0f;
            creature->max_health = 1500.0f;

            locals.formation_offset = 2;
            chain_target_offset = -0x100;
            chain_link_idx = root_slot_idx;
            lizard_chain_zero_velocity.set(0.0f, 0.0f);
            child_tint.set(0.6f, 0.6f, 0.31f, 1.0f);
            do {
                child_slot_idx = creature_alloc_slot();
                creature = &creature_pool[child_slot_idx];
                creature->target_offset.x = (float)chain_target_offset;
                creature->ai_mode = CREATURE_AI_FOLLOW_LINK;
                creature->link_index = chain_link_idx;
                creature->target_offset.y = -256.0f;
                float angle =
                    (float)locals.formation_offset * 0.39269909f;
                scaled_orbit_x = (float)cos(angle);
                orbit_direction.y = (float)sin(angle);
                orbit_direction.x = scaled_orbit_x * 256.0f;
                orbit_direction.y = orbit_direction.y * 256.0f;
                lizard_chain_position.x = orbit_direction.x + pos->x;
                lizard_chain_position.y = orbit_direction.y + pos->y;
                *(creature_spawn_vec2_t *)&creature->position = lizard_chain_position;
                *(creature_spawn_vec2_t *)&creature->velocity = lizard_chain_zero_velocity;
                creature->health = 60.0f;
                *(creature_tint_t *)&creature->color = child_tint;
                creature->reward_value = 60.0f;
                creature->max_health = 60.0f;
                chain_target_offset = chain_target_offset + 0x40;
                locals.formation_offset = locals.formation_offset + 2;
                creature->collision_flag = 0;
                creature->collision_timer = 0.0f;
                creature->active = 1;
                creature->state_flag = 1;
                creature->lifecycle_stage = 16.0f;
                creature->attack_cooldown = 0.0f;
                creature->type_id = CREATURE_TYPE_LIZARD;
                creature->move_speed = 2.4f;
                creature->size = 50.0f;
                creature->contact_damage = 14.0f;
                chain_link_idx = child_slot_idx;
            } while (chain_target_offset < 0);
            creature_pool[root_slot_idx].link_index = child_slot_idx;
    }

    if (template_id == SPAWN_ID_FORMATION_CHAIN_ALIEN_10_13) {
                int alien_chain_cursor;
                creature->type_id = CREATURE_TYPE_ALIEN;
                alien_chain_cursor = terrain_texture_height / 2;
                creature->ai_mode = CREATURE_AI_CHASE_PLAYER;
                chain_position.set(-10.0f, (float)alien_chain_cursor);
                *(creature_spawn_vec2_t *)&creature->position = chain_position;
                creature->health = 200.0f;
                creature->move_speed = 2.0f;
                creature->reward_value = 600.0f;
                child_tint.set(0.6f, 0.8f, 0.91f, 1.0f);
                *(creature_tint_t *)&creature->color = child_tint;
                creature->size = 40.0f;
                creature->contact_damage = 20.0f;
                zero_velocity.set(0.0f, 0.0f);
                child_tint.set(0.4f, 0.7f, 0.11f, 1.0f);
                alien_chain_cursor = 2;
                orbit_direction.x = (float)cos(0.0f);
                orbit_direction.y = (float)sin(0.0f);
                orbit_direction.x = orbit_direction.x * 256.0f;
                orbit_direction.y = orbit_direction.y * 256.0f;
                chain_position.x = orbit_direction.x + pos->x;
                chain_position.y = orbit_direction.y + pos->y;
                *(creature_spawn_vec2_t *)&creature->position = chain_position;
                creature->max_health = 200.0f;
                creature->ai_mode = CREATURE_AI_ORBIT_LINK;
                chain_link_idx = root_slot_idx;
                do {
                    child_slot_idx = creature_alloc_slot();
                    creature = &creature_pool[child_slot_idx];
                    float angle = (float)alien_chain_cursor * 0.34906587f;
                    creature->ai_mode = CREATURE_AI_ORBIT_LINK;
                    creature->link_index = chain_link_idx;
                    creature->orbit_angle = 3.1415927f;
                    creature->orbit_radius.raw_u32 = 0x41200000;
                    orbit_direction.x = (float)cos(angle);
                    orbit_direction.y = (float)sin(angle);
                    scaled_orbit_x = orbit_direction.x * 256.0f;
                    orbit_direction.y = orbit_direction.y * 256.0f;
                    chain_position.x = scaled_orbit_x + pos->x;
                    chain_position.y = orbit_direction.y + pos->y;
                    *(creature_spawn_vec2_t *)&creature->position = chain_position;
                    *(creature_spawn_vec2_t *)&creature->velocity = zero_velocity;
                    creature->health = 60.0f;
                    *(creature_tint_t *)&creature->color = child_tint;
                    creature->reward_value = 60.0f;
                    creature->max_health = 60.0f;
                    alien_chain_cursor = alien_chain_cursor + 2;
                    creature->collision_flag = 0;
                    creature->collision_timer = 0.0f;
                    creature->active = 1;
                    creature->state_flag = 1;
                    creature->lifecycle_stage = 16.0f;
                    creature->attack_cooldown = 0.0f;
                    creature->type_id = CREATURE_TYPE_ALIEN;
                    creature->move_speed = 2.0f;
                    creature->size = 50.0f;
                    creature->contact_damage = 4.0f;
                    chain_link_idx = child_slot_idx;
                } while (alien_chain_cursor < 0x16);
                creature_pool[root_slot_idx].link_index = child_slot_idx;
    }

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
                } else if (template_id == SPAWN_ID_ALIEN_CONST_BROWN_TRANSPARENT_0F) {
                    creature->type_id = CREATURE_TYPE_ALIEN;
                    creature->position.x = pos->x;
                    creature->position.y = pos->y;
                    SET_ROOT_STATS_WITH_TINT(CREATURE_TYPE_ALIEN, 20.0f, 2.9f, 60.0f,
                                             0.66499996f, 0.385f, 0.259f, 0.56f, 50.0f, 35.0f);
                    creature->ai_mode = CREATURE_AI_ORBIT_PLAYER;
                    creature->max_health = 20.0f;
                } else if (template_id == SPAWN_ID_FORMATION_GRID_ALIEN_BRONZE_18) {
                    creature = &creature_pool[root_slot_idx];
                    INIT_GRID_ROOT(CREATURE_TYPE_ALIEN, CREATURE_AI_CHASE_PLAYER,
                                   0.7f, 0.8f, 0.31f, 500.0f, 2.0f, 40.0f);
                    SPAWN_GRID(CREATURE_AI_FOLLOW_LINK, CREATURE_TYPE_ALIEN, 260.0f,
                               0.7125f, 0.41250002f, 0.2775f, 3.8f, 0.6f, 50.0f, 35.0f);
    }

    if (template_id == SPAWN_ID_SPIDER_SP2_SPLITTER_01) {
                    creature->type_id = CREATURE_TYPE_SPIDER_SP2;
                    creature->flags = CREATURE_FLAG_SPLIT_ON_DEATH;
                    creature->size = 80.0f;
                    creature->health = 400.0f;
                    creature->move_speed = 2.0f;
                    creature->reward_value = 1000.0f;
                    creature->color.a = 1.0f;
                    creature->color.r = 0.8f;
                    creature->color.g = 0.7f;
                    creature->color.b = 0.4f;
                    creature->contact_damage = 17.0f;
                } else if (template_id == SPAWN_ID_ALIEN_SPAWNER_CHILD_32_SLOW_0A) {
                    INIT_ALIEN_SPAWNER(2.0f, 100, 5.0f, SPAWN_ID_SPIDER_SP1_RANDOM_32,
                                       55.0f, 1000.0f, 1.5f, 3000.0f, 0.8f, 0.7f, 0.4f);
                } else if (template_id == SPAWN_ID_ALIEN_SPAWNER_CHILD_3C_SLOW_0B) {
                    INIT_ALIEN_SPAWNER(2.0f, 100, 6.0f, SPAWN_ID_SPIDER_SP1_CONST_RANGED_VARIANT_3C,
                                       65.0f, 3500.0f, 1.5f, 5000.0f, 0.9f, 0.1f, 0.1f);
                } else if (template_id == SPAWN_ID_ALIEN_SPAWNER_CHILD_32_FAST_10) {
                    INIT_ALIEN_SPAWNER(1.5f, 100, 2.3f, SPAWN_ID_SPIDER_SP1_RANDOM_32,
                                       32.0f, 50.0f, 2.8f, 800.0f, 0.9f, 0.8f, 0.4f);
                } else if (template_id == SPAWN_ID_ALIEN_SPAWNER_RING_24_0E) {
                    INIT_ALIEN_SPAWNER(1.5f, 0x40, 1.05f, SPAWN_ID_AI1_LIZARD_BLUE_TINT_1C,
                                       32.0f, 50.0f, 2.8f, 5000.0f, 0.9f, 0.8f, 0.4f);
                    chain_position.set(0.0f, 0.0f);
                    child_tint.set(1.0f, 0.3f, 0.3f, 1.0f);
                    ring_member_idx = 0;
                    do {
                        child_slot_idx = creature_alloc_slot();
                        creature = &creature_pool[child_slot_idx];
                        float angle = (float)ring_member_idx * 0.2617994f;
                        creature->ai_mode = CREATURE_AI_FOLLOW_LINK;
                        creature->heading = 0.0f;
                        creature->anim_phase = 0.0f;
                        creature->link_index = root_slot_idx;
                        creature->target_offset.x = (float)cos(angle) * 100.0f;
                        creature->target_offset.y = (float)sin(angle) * 100.0f;
                        creature->position.x = pos->x;
                        creature->position.y = pos->y;
                        *(creature_spawn_vec2_t *)&creature->velocity = chain_position;
                        creature->collision_flag = 0;
                        creature->health = 40.0f;
                        creature->max_health = 40.0f;
                        *(creature_tint_t *)&creature->color = child_tint;
                        creature->collision_timer = 0.0f;
                        creature->active = 1;
                        creature->state_flag = 1;
                        creature->lifecycle_stage = 16.0f;
                        creature->attack_cooldown = 0.0f;
                        creature->type_id = CREATURE_TYPE_ALIEN;
                        creature->move_speed = 4.0f;
                        creature->reward_value = 350.0f;
                        creature->size = 35.0f;
                        creature->contact_damage = 30.0f;
                        ring_member_idx = ring_member_idx + 1;
                    } while (ring_member_idx < 0x18);
                } else if (template_id == SPAWN_ID_ALIEN_SPAWNER_CHILD_31_FAST_0C) {
                    INIT_ALIEN_SPAWNER(1.5f, 100, 2.0f, SPAWN_ID_LIZARD_RANDOM_31,
                                       32.0f, 50.0f, 2.8f, 1000.0f, 0.9f, 0.8f, 0.4f);
                } else if (template_id == SPAWN_ID_ALIEN_SPAWNER_CHILD_31_SLOW_0D) {
                    INIT_ALIEN_SPAWNER(2.0f, 100, 6.0f, SPAWN_ID_LIZARD_RANDOM_31,
                                       32.0f, 50.0f, 1.3f, 1000.0f, 0.9f, 0.8f, 0.4f);
                } else if (template_id == SPAWN_ID_ALIEN_SPAWNER_CHILD_1D_LIMITED_09) {
                    INIT_ALIEN_SPAWNER(1.0f, 0x10, 2.0f, SPAWN_ID_ALIEN_RANDOM_1D,
                                       40.0f, 450.0f, 2.0f, 1000.0f, 1.0f, 1.0f, 1.0f);
                } else if (template_id == SPAWN_ID_ALIEN_SPAWNER_CHILD_1D_FAST_07) {
                    INIT_ALIEN_SPAWNER(1.0f, 100, 2.2f, SPAWN_ID_ALIEN_RANDOM_1D,
                                       50.0f, 1000.0f, 2.0f, 3000.0f, 1.0f, 1.0f, 1.0f);
                } else if (template_id == SPAWN_ID_ALIEN_SPAWNER_CHILD_1D_SLOW_08) {
                    INIT_ALIEN_SPAWNER(1.0f, 100, 2.8f, SPAWN_ID_ALIEN_RANDOM_1D,
                                       50.0f, 1000.0f, 2.0f, 3000.0f, 1.0f, 1.0f, 1.0f);
                } else if (template_id == SPAWN_ID_AI1_ALIEN_BLUE_TINT_1A) {
                    creature->type_id = CREATURE_TYPE_ALIEN;
                    creature->size = 50.0f;
                    creature->ai_mode = CREATURE_AI_ORBIT_PLAYER_TIGHT;
                    creature->health = 50.0f;
                    creature->move_speed = 2.4f;
                    creature->reward_value = 125.0f;
                    creature->color.a = 1.0f;
                    random_heading_roll = crt_rand();
                    float random_tint_scalar =
                        (float)(random_heading_roll % 0x28) * 0.01f + 0.5f;
                    creature->color.r = random_tint_scalar;
                    creature->color.g = random_tint_scalar;
                    creature->color.b = 1.0f;
                    creature->contact_damage = 5.0f;
                } else if (template_id == SPAWN_ID_AI1_SPIDER_SP1_BLUE_TINT_1B) {
                    creature->type_id = CREATURE_TYPE_SPIDER_SP1;
                    creature->size = 50.0f;
                    creature->ai_mode = CREATURE_AI_ORBIT_PLAYER_TIGHT;
                    creature->health = 40.0f;
                    creature->move_speed = 2.4f;
                    creature->reward_value = 125.0f;
                    creature->color.a = 1.0f;
                    random_heading_roll = crt_rand();
                    float random_tint_scalar =
                        (float)(random_heading_roll % 0x28) * 0.01f + 0.5f;
                    creature->color.r = random_tint_scalar;
                    creature->color.g = random_tint_scalar;
                    creature->color.b = 1.0f;
                    creature->contact_damage = 5.0f;
                } else if (template_id == SPAWN_ID_AI1_LIZARD_BLUE_TINT_1C) {
                    creature->type_id = CREATURE_TYPE_LIZARD;
                    creature->size = 50.0f;
                    creature->ai_mode = CREATURE_AI_ORBIT_PLAYER_TIGHT;
                    creature->health = 50.0f;
                    creature->move_speed = 2.4f;
                    creature->reward_value = 125.0f;
                    creature->color.a = 1.0f;
                    random_heading_roll = crt_rand();
                    float random_tint_scalar =
                        (float)(random_heading_roll % 0x28) * 0.01f + 0.5f;
                    creature->color.r = random_tint_scalar;
                    creature->color.g = random_tint_scalar;
                    creature->color.b = 1.0f;
                    creature->contact_damage = 5.0f;
                } else if (template_id == SPAWN_ID_ZOMBIE_RANDOM_41) {
                    creature->type_id = CREATURE_TYPE_ZOMBIE;
                    random_heading_roll = crt_rand();
                    float random_size = (float)(random_heading_roll % 0x1e + 0x28);
                    creature->size = random_size;
                    creature->health = random_size * 1.1428572f + 10.0f;
                    creature->color.a = 1.0f;
                    creature->move_speed = random_size * 0.0025f + 0.9f;
                    creature->reward_value = random_size + random_size + 50.0f;
                    random_heading_roll = crt_rand();
                    float random_tint_scalar =
                        (float)(random_heading_roll % 0x28) * 0.01f + 0.6f;
                    creature->color.r = random_tint_scalar;
                    creature->color.g = random_tint_scalar;
                    creature->color.b = random_tint_scalar;
                    RAND_FIELD(creature->contact_damage, 10, 1.0f, 4.0f);
                } else if (template_id == SPAWN_ID_LIZARD_RANDOM_31) {
                    creature->type_id = CREATURE_TYPE_LIZARD;
                    random_heading_roll = crt_rand();
                    float random_size = (float)(random_heading_roll % 0x1e + 0x28);
                    creature->size = random_size;
                    creature->health = random_size * 1.1428572f + 10.0f;
                    creature->color.a = 1.0f;
                    RAND_FIELD(creature->move_speed, 0x12, 0.1f, 1.1f);
                    creature->reward_value = creature->size + creature->size + 50.0f;
                    creature->color.b = 0.38f;
                    random_heading_roll = crt_rand();
                    float random_tint_scalar =
                        (float)(random_heading_roll % 0x1e) * 0.01f + 0.6f;
                    creature->color.r = random_tint_scalar;
                    creature->color.g = random_tint_scalar;
                    creature->contact_damage = creature->size * 0.14f + 4.0f;
                } else if (template_id == SPAWN_ID_SPIDER_SP1_RANDOM_32) {
                    creature->type_id = CREATURE_TYPE_SPIDER_SP1;
                    random_heading_roll = crt_rand();
                    float random_size = (float)(random_heading_roll % 0x19 + 0x28);
                    creature->size = random_size;
                    creature->health = random_size + 10.0f;
                    creature->color.a = 1.0f;
                    RAND_FIELD(creature->move_speed, 0x11, 0.1f, 1.1f);
                    creature->reward_value = creature->size + creature->size + 50.0f;
                    random_heading_roll = crt_rand();
                    float random_tint_scalar =
                        (float)(random_heading_roll % 0x28) * 0.01f + 0.6f;
                    creature->color.r = random_tint_scalar;
                    creature->color.g = random_tint_scalar;
                    creature->color.b = random_tint_scalar;
                    creature->contact_damage = creature->size * 0.14f + 4.0f;
                } else if (template_id == SPAWN_ID_SPIDER_SP1_RANDOM_RED_33) {
                    creature->type_id = CREATURE_TYPE_SPIDER_SP1;
                    random_heading_roll = crt_rand();
                    float random_size = (float)(random_heading_roll % 0x0f + 0x2d);
                    creature->size = random_size;
                    creature->health = random_size * 1.1428572f + 20.0f;
                    RAND_FIELD(creature->move_speed, 0x12, 0.1f, 1.1f);
                    creature->color.a = 1.0f;
                    creature->reward_value = creature->size + creature->size + 50.0f;
                    RAND_FIELD(creature->color.r, 0x28, 0.01f, 0.6f);
                    creature->color.g = 0.5f;
                    creature->color.b = 0.5f;
                    RAND_FIELD(creature->contact_damage, 10, 1.0f, 4.0f);
                } else if (template_id == SPAWN_ID_SPIDER_SP1_RANDOM_GREEN_34) {
                    creature->type_id = CREATURE_TYPE_SPIDER_SP1;
                    random_heading_roll = crt_rand();
                    float random_size = (float)(random_heading_roll % 0x14 + 0x28);
                    creature->size = random_size;
                    creature->health = random_size * 1.1428572f + 20.0f;
                    RAND_FIELD(creature->move_speed, 0x12, 0.1f, 1.1f);
                    creature->color.a = 1.0f;
                    creature->reward_value = creature->size + creature->size + 50.0f;
                    creature->color.r = 0.5f;
                    RAND_FIELD(creature->color.g, 0x28, 0.01f, 0.6f);
                    creature->color.b = 0.5f;
                    RAND_FIELD(creature->contact_damage, 10, 1.0f, 4.0f);
                } else if (template_id == SPAWN_ID_ALIEN_RANDOM_GREEN_20) {
                    creature->type_id = CREATURE_TYPE_ALIEN;
                    random_heading_roll = crt_rand();
                    float random_size = (float)(random_heading_roll % 0x1e + 0x28);
                    creature->size = random_size;
                    creature->health = random_size * 1.1428572f + 20.0f;
                    RAND_FIELD(creature->move_speed, 0x12, 0.1f, 1.1f);
                    creature->color.a = 1.0f;
                    creature->color.r = 0.3f;
                    creature->reward_value = creature->size + creature->size + 50.0f;
                    RAND_FIELD(creature->color.g, 0x28, 0.01f, 0.6f);
                    creature->color.b = 0.3f;
                    RAND_FIELD(creature->contact_damage, 10, 1.0f, 4.0f);
                } else if (template_id == SPAWN_ID_SPIDER_SP1_RANDOM_03) {
                    creature->type_id = CREATURE_TYPE_SPIDER_SP1;
                    RAND_FIELD_INT_BASE(creature->size, 0x0f, 0x26);
                    creature->health = creature->size * 1.1428572f + 20.0f;
                    RAND_FIELD(creature->move_speed, 0x12, 0.1f, 1.1f);
                    creature->color.a = 1.0f;
                    creature->color.r = 0.6f;
                    creature->color.g = 0.6f;
                    creature->reward_value = creature->size + creature->size + 50.0f;
                    RAND_FIELD(creature->color.b, 0x19, 0.01f, 0.8f);
                    CLAMP_TINT_COMPONENT(creature->color.r);
                    CLAMP_TINT_COMPONENT(creature->color.g);
                    CLAMP_TINT_COMPONENT(creature->color.b);
                    CLAMP_TINT_COMPONENT(creature->color.a);
                    RAND_FIELD(creature->contact_damage, 10, 1.0f, 4.0f);
                } else if (template_id == SPAWN_ID_SPIDER_SP2_RANDOM_05) {
                    creature->type_id = CREATURE_TYPE_SPIDER_SP2;
                    RAND_FIELD_INT_BASE(creature->size, 0x0f, 0x26);
                    creature->health = creature->size * 1.1428572f + 20.0f;
                    RAND_FIELD(creature->move_speed, 0x12, 0.1f, 1.1f);
                    creature->color.a = 1.0f;
                    creature->color.r = 0.6f;
                    creature->color.g = 0.6f;
                    creature->reward_value = creature->size + creature->size + 50.0f;
                    RAND_FIELD(creature->color.b, 0x19, 0.01f, 0.8f);
                    CLAMP_TINT_COMPONENT(creature->color.r);
                    CLAMP_TINT_COMPONENT(creature->color.g);
                    CLAMP_TINT_COMPONENT(creature->color.b);
                    CLAMP_TINT_COMPONENT(creature->color.a);
                    RAND_FIELD(creature->contact_damage, 10, 1.0f, 4.0f);
                } else if (template_id == SPAWN_ID_LIZARD_RANDOM_04) {
                    creature->type_id = CREATURE_TYPE_LIZARD;
                    RAND_FIELD_INT_BASE(creature->size, 0x0f, 0x26);
                    creature->health = creature->size * 1.1428572f + 20.0f;
                    RAND_FIELD(creature->move_speed, 0x12, 0.1f, 1.1f);
                    creature->color.a = 1.0f;
                    creature->color.r = 0.67f;
                    creature->color.g = 0.67f;
                    creature->color.b = 1.0f;
                    creature->reward_value = creature->size + creature->size + 50.0f;
                    RAND_FIELD(creature->contact_damage, 10, 1.0f, 4.0f);
                } else if (template_id == SPAWN_ID_ALIEN_RANDOM_06) {
                    creature->type_id = CREATURE_TYPE_ALIEN;
                    RAND_FIELD_INT_BASE(creature->size, 0x0f, 0x26);
                    creature->health = creature->size * 1.1428572f + 20.0f;
                    RAND_FIELD(creature->move_speed, 0x12, 0.1f, 1.1f);
                    creature->color.a = 1.0f;
                    creature->color.r = 0.6f;
                    creature->color.g = 0.6f;
                    creature->reward_value = creature->size + creature->size + 50.0f;
                    RAND_FIELD(creature->color.b, 0x19, 0.01f, 0.8f);
                    CLAMP_TINT_COMPONENT(creature->color.r);
                    CLAMP_TINT_COMPONENT(creature->color.g);
                    CLAMP_TINT_COMPONENT(creature->color.b);
                    CLAMP_TINT_COMPONENT(creature->color.a);
                    RAND_FIELD(creature->contact_damage, 10, 1.0f, 4.0f);
                } else if (template_id == SPAWN_ID_SPIDER_SP2_RANDOM_35) {
                    creature->type_id = CREATURE_TYPE_SPIDER_SP2;
                    RAND_FIELD_INT_BASE(creature->size, 10, 0x1e);
                    creature->health = creature->size * 1.1428572f + 20.0f;
                    RAND_FIELD(creature->move_speed, 0x12, 0.1f, 1.1f);
                    creature->color.a = 1.0f;
                    creature->color.b = 0.8f;
                    creature->reward_value = creature->size + creature->size + 50.0f;
                    RAND_FIELD(creature->color.g, 0x14, 0.01f, 0.8f);
                    creature->color.r = 0.8f;
                    RAND_FIELD(creature->contact_damage, 10, 1.0f, 4.0f);
                } else if (template_id == SPAWN_ID_LIZARD_RANDOM_2E) {
                    creature->type_id = CREATURE_TYPE_LIZARD;
                    RAND_FIELD_INT_BASE(creature->size, 0x1e, 0x28);
                    creature->health = creature->size * 1.1428572f + 20.0f;
                    RAND_FIELD(creature->move_speed, 0x12, 0.1f, 1.1f);
                    creature->color.a = 1.0f;
                    creature->reward_value = creature->size + creature->size + 50.0f;
                    RAND_FIELD(creature->color.r, 0x28, 0.01f, 0.6f);
                    RAND_FIELD(creature->color.g, 0x28, 0.01f, 0.6f);
                    RAND_FIELD(creature->color.b, 0x28, 0.01f, 0.6f);
                    RAND_FIELD(creature->contact_damage, 10, 1.0f, 4.0f);
                } else if (template_id == SPAWN_ID_ALIEN_AI7_ORBITER_36) {
                    creature->type_id = CREATURE_TYPE_ALIEN;
                    creature->size = 50.0f;
                    creature->ai_mode = CREATURE_AI_HOLD_TIMER;
                    creature->orbit_radius.radius = 1.5f;
                    creature->health = 10.0f;
                    creature->move_speed = 1.8f;
                    creature->reward_value = 150.0f;
                    creature->color.a = 1.0f;
                    RAND_FIELD(creature->color.g, 5, 0.01f, 0.65f);
                    creature->color.r = 0.65f;
                    creature->color.b = 0.95f;
                    creature->contact_damage = 40.0f;
                } else if (template_id == SPAWN_ID_ALIEN_RANDOM_1D) {
                    creature->type_id = CREATURE_TYPE_ALIEN;
                    RAND_FIELD_INT_BASE(creature->size, 0x14, 0x23);
                    creature->health = creature->size * 1.1428572f + 10.0f;
                    RAND_FIELD(creature->move_speed, 0x0f, 0.1f, 1.1f);
                    RAND_FIELD_INT_BASE(creature->reward_value, 100, 0x32);
                    creature->color.a = 1.0f;
                    RAND_FIELD(creature->color.r, 0x32, 0.001f, 0.6f);
                    RAND_FIELD(creature->color.g, 0x32, 0.01f, 0.5f);
                    RAND_FIELD(creature->color.b, 0x32, 0.001f, 0.6f);
                    RAND_FIELD(creature->contact_damage, 10, 1.0f, 4.0f);
                } else if (template_id == SPAWN_ID_ALIEN_RANDOM_1E) {
                    creature->type_id = CREATURE_TYPE_ALIEN;
                    RAND_FIELD_INT_BASE(creature->size, 0x1e, 0x23);
                    creature->health = creature->size * 2.2857144f + 10.0f;
                    RAND_FIELD(creature->move_speed, 0x11, 0.1f, 1.5f);
                    RAND_FIELD_INT_BASE(creature->reward_value, 200, 0x32);
                    creature->color.a = 1.0f;
                    RAND_FIELD(creature->color.r, 0x32, 0.001f, 0.6f);
                    RAND_FIELD(creature->color.g, 0x32, 0.001f, 0.6f);
                    RAND_FIELD(creature->color.b, 0x32, 0.01f, 0.5f);
                    RAND_FIELD(creature->contact_damage, 0x1e, 1.0f, 4.0f);
                } else if (template_id == SPAWN_ID_ALIEN_RANDOM_1F) {
                    creature->type_id = CREATURE_TYPE_ALIEN;
                    RAND_FIELD_INT_BASE(creature->size, 0x1e, 0x2d);
                    creature->health = creature->size * 3.7142856f + 30.0f;
                    RAND_FIELD(creature->move_speed, 0x15, 0.1f, 1.6f);
                    RAND_FIELD_INT_BASE(creature->reward_value, 200, 0x50);
                    creature->color.a = 1.0f;
                    RAND_FIELD(creature->color.r, 0x32, 0.01f, 0.5f);
                    RAND_FIELD(creature->color.g, 0x32, 0.001f, 0.6f);
                    RAND_FIELD(creature->color.b, 0x32, 0.001f, 0.6f);
                    RAND_FIELD(creature->contact_damage, 0x23, 1.0f, 8.0f);
                } else if (template_id == SPAWN_ID_ALIEN_CONST_GREEN_24) {
                    SET_ROOT_STATS_WITH_TINT(CREATURE_TYPE_ALIEN, 20.0f, 2.0f, 110.0f,
                                             0.1f, 0.7f, 0.11f, 1.0f, 50.0f, 4.0f);
                } else if (template_id == SPAWN_ID_ALIEN_CONST_GREEN_SMALL_25) {
                    SET_ROOT_STATS_WITH_TINT(CREATURE_TYPE_ALIEN, 25.0f, 2.5f, 125.0f,
                                             0.1f, 0.8f, 0.11f, 1.0f, 30.0f, 3.0f);
                } else if (template_id == SPAWN_ID_ALIEN_CONST_PALE_GREEN_26) {
                    SET_ROOT_STATS_WITH_TINT(CREATURE_TYPE_ALIEN, 50.0f, 2.2f, 125.0f,
                                             0.6f, 0.8f, 0.6f, 1.0f, 45.0f, 10.0f);
                } else if (template_id == SPAWN_ID_ALIEN_CONST_WEAPON_BONUS_27) {
                    creature->type_id = CREATURE_TYPE_ALIEN;
                    creature->health = 50.0f;
                    creature->move_speed = 2.1f;
                    child_tint.set(1.0f, 0.8f, 0.1f, 1.0f);
                    creature->flags = CREATURE_FLAG_BONUS_ON_DEATH;
                    creature->reward_value = 125.0f;
                    *(creature_tint_t *)&creature->color = child_tint;
                    creature_bonus_args_t *bonus_args =
                        &creature->bonus_args;
                    bonus_args->bonus_id = 3;
                    bonus_args->duration_override = 5;
                    creature->size = 45.0f;
                    creature->contact_damage = 10.0f;
                } else if (template_id == SPAWN_ID_ALIEN_CONST_PURPLE_GHOST_21) {
                    SET_ROOT_STATS_WITH_TINT(CREATURE_TYPE_ALIEN, 53.0f, 1.7f, 120.0f,
                                             0.7f, 0.1f, 0.51f, 0.5f, 55.0f, 8.0f);
                } else if (template_id == SPAWN_ID_ALIEN_CONST_GREEN_GHOST_22) {
                    SET_ROOT_STATS_WITH_TINT(CREATURE_TYPE_ALIEN, 25.0f, 1.7f, 150.0f,
                                             0.1f, 0.7f, 0.51f, 0.05f, 50.0f, 8.0f);
                } else if (template_id == SPAWN_ID_ALIEN_CONST_GREEN_GHOST_SMALL_23) {
                    SET_ROOT_STATS_WITH_TINT(CREATURE_TYPE_ALIEN, 5.0f, 1.7f, 180.0f,
                                             0.1f, 0.7f, 0.51f, 0.04f, 45.0f, 8.0f);
                } else if (template_id == SPAWN_ID_ALIEN_CONST_PURPLE_28) {
                    creature->type_id = CREATURE_TYPE_ALIEN;
                    creature->health = 50.0f;
                    child_tint.set(0.7f, 0.1f, 0.51f, 1.0f);
                    creature->move_speed = 1.7f;
                    creature->reward_value = 150.0f;
                    *(creature_tint_t *)&creature->color = child_tint;
                    creature->size = 55.0f;
                    creature->contact_damage = 8.0f;
                } else if (template_id == SPAWN_ID_ALIEN_CONST_GREY_BRUTE_29) {
                    SET_ROOT_STATS_WITH_TINT(CREATURE_TYPE_ALIEN, 800.0f, 2.5f, 450.0f,
                                             0.8f, 0.8f, 0.8f, 1.0f, 70.0f, 20.0f);
                } else if (template_id == SPAWN_ID_ALIEN_CONST_GREY_FAST_2A) {
                    SET_ROOT_STATS_WITH_TINT(CREATURE_TYPE_ALIEN, 50.0f, 3.1f, 300.0f,
                                             0.3f, 0.3f, 0.3f, 1.0f, 60.0f, 8.0f);
                } else if (template_id == SPAWN_ID_ALIEN_CONST_RED_FAST_2B) {
                    creature->type_id = CREATURE_TYPE_ALIEN;
                    creature->health = 30.0f;
                    child_tint.set(1.0f, 0.3f, 0.3f, 1.0f);
                    creature->move_speed = 3.6f;
                    creature->reward_value = 450.0f;
                    *(creature_tint_t *)&creature->color = child_tint;
                    creature->size = 35.0f;
                    creature->contact_damage = 20.0f;
                } else if (template_id == SPAWN_ID_ALIEN_CONST_RED_BOSS_2C) {
                    SET_ROOT_STATS_WITH_TINT(CREATURE_TYPE_ALIEN, 3800.0f, 2.0f, 1500.0f,
                                             0.85f, 0.2f, 0.2f, 1.0f, 80.0f, 40.0f);
                } else if (template_id == SPAWN_ID_ALIEN_CONST_CYAN_AI2_2D) {
                    SET_ROOT_STATS_WITH_TINT(CREATURE_TYPE_ALIEN, 45.0f, 3.1f, 200.0f,
                                             0.0f, 0.9f, 0.8f, 1.0f, 38.0f, 3.0f);
                    creature->ai_mode = CREATURE_AI_CHASE_PLAYER;
                } else if (template_id == SPAWN_ID_LIZARD_CONST_GREY_2F) {
                    SET_ROOT_STATS_WITH_TINT(CREATURE_TYPE_LIZARD, 20.0f, 2.5f, 150.0f,
                                             0.8f, 0.8f, 0.8f, 1.0f, 45.0f, 4.0f);
                } else if (template_id == SPAWN_ID_LIZARD_CONST_YELLOW_BOSS_30) {
                    SET_ROOT_STATS_WITH_TINT(CREATURE_TYPE_LIZARD, 1000.0f, 2.0f, 400.0f,
                                             0.9f, 0.8f, 0.1f, 1.0f, 65.0f, 10.0f);
                } else if (template_id == SPAWN_ID_SPIDER_SP1_CONST_RED_BOSS_3B) {
                    SET_ROOT_STATS_WITH_TINT(CREATURE_TYPE_SPIDER_SP1, 1200.0f, 2.0f, 4000.0f,
                                             0.9f, 0.0f, 0.0f, 1.0f, 70.0f, 20.0f);
                } else if (template_id == SPAWN_ID_SPIDER_SP1_CONST_RANGED_VARIANT_3C) {
                    creature->type_id = CREATURE_TYPE_SPIDER_SP1;
                    creature->flags = CREATURE_FLAG_RANGED_ATTACK_VARIANT;
                    creature->orbit_angle = 0.4f;
                    creature->orbit_radius.projectile_type = PROJECTILE_TYPE_SPIDER_PLASMA;
                    creature->health = 200.0f;
                    creature->move_speed = 2.0f;
                    creature->reward_value = 200.0f;
                    child_tint.set(0.9f, 0.1f, 0.1f, 1.0f);
                    *(creature_tint_t *)&creature->color = child_tint;
                    creature->size = 40.0f;
                    creature->contact_damage = 20.0f;
                    creature->ai_mode = CREATURE_AI_CHASE_PLAYER;
                } else if (template_id == SPAWN_ID_SPIDER_SP1_RANDOM_3D) {
                    creature->type_id = CREATURE_TYPE_SPIDER_SP1;
                    creature->health = 70.0f;
                    creature->move_speed = 2.6f;
                    creature->reward_value = 120.0f;
                    creature->color.a = 1.0f;
                    random_heading_roll = crt_rand();
                    float random_tint_scalar =
                        (float)(random_heading_roll % 0x14) * 0.01f + 0.8f;
                    creature->color.r = random_tint_scalar;
                    creature->color.b = random_tint_scalar;
                    creature->color.g = random_tint_scalar;
                    RAND_FIELD_INT_BASE(creature->size, 7, 0x2d);
                    creature->contact_damage = creature->size * 0.22f;
                } else if (template_id == SPAWN_ID_SPIDER_SP1_CONST_WHITE_FAST_3E) {
                    SET_ROOT_STATS_WITH_TINT(CREATURE_TYPE_SPIDER_SP1, 1000.0f, 2.8f, 500.0f,
                                             1.0f, 1.0f, 1.0f, 1.0f, 64.0f, 40.0f);
                } else if (template_id == SPAWN_ID_ZOMBIE_BOSS_SPAWNER_00) {
                    creature->type_id = CREATURE_TYPE_ZOMBIE;
                    creature->flags = CREATURE_FLAG_ANIM_PING_PONG | CREATURE_FLAG_ANIM_LONG_STRIP;
                    creature->health = 8500.0f;
                    creature->move_speed = 1.3f;
                    creature->reward_value = 6600.0f;
                    child_tint.set(0.6f, 0.6f, 1.0f, 0.8f);
                    *(creature_tint_t *)&creature->color = child_tint;
                    creature->size = 64.0f;
                    creature->contact_damage = 50.0f;
                    child_slot_idx = creature_spawn_slot_alloc();
                    creature->link_index = child_slot_idx;
                    creature_spawn_slot_t *spawn_slot =
                        &creature_spawn_slot_table[child_slot_idx];
                    spawn_slot->timer_s = 1.0f;
                    spawn_slot->count = 0;
                    spawn_slot->limit = 0x32c;
                    spawn_slot->interval_s = 0.7f;
                    spawn_slot->template_id = SPAWN_ID_ZOMBIE_RANDOM_41;
                    spawn_slot->owner = creature;
                } else if (template_id == SPAWN_ID_SPIDER_SP1_AI7_TIMER_38) {
                    creature->type_id = CREATURE_TYPE_SPIDER_SP1;
                    creature->flags = CREATURE_FLAG_AI7_LINK_TIMER;
                    creature->link_index = 0;
                    creature->health = 50.0f;
                    creature->move_speed = 4.8f;
                    creature->reward_value = 433.0f;
                    child_tint.set(1.0f, 0.75f, 0.1f, 1.0f);
                    *(creature_tint_t *)&creature->color = child_tint;
                    creature->size = (float)(crt_rand() % 4 + 0x29);
                    creature->contact_damage = 10.0f;
                } else if (template_id == SPAWN_ID_SPIDER_SP2_RANGED_VARIANT_37) {
                    creature->type_id = CREATURE_TYPE_SPIDER_SP2;
                    creature->flags = CREATURE_FLAG_RANGED_ATTACK_VARIANT;
                    creature->link_index = 0;
                    creature->health = 50.0f;
                    creature->move_speed = 3.2f;
                    creature->reward_value = 433.0f;
                    child_tint.set(1.0f, 0.75f, 0.1f, 1.0f);
                    *(creature_tint_t *)&creature->color = child_tint;
                    creature->size = (float)(crt_rand() % 4 + 0x29);
                    creature->contact_damage = 10.0f;
                } else if (template_id == SPAWN_ID_SPIDER_SP1_AI7_TIMER_WEAK_39) {
                    creature->type_id = CREATURE_TYPE_SPIDER_SP1;
                    creature->flags = CREATURE_FLAG_AI7_LINK_TIMER;
                    creature->link_index = 0;
                    creature->health = 4.0f;
                    creature->move_speed = 4.8f;
                    creature->reward_value = 50.0f;
                    child_tint.set(0.8f, 0.65f, 0.1f, 1.0f);
                    *(creature_tint_t *)&creature->color = child_tint;
                    creature->size = (float)(crt_rand() % 4 + 0x1a);
                    creature->contact_damage = 10.0f;
                } else if (template_id == SPAWN_ID_SPIDER_SP1_CONST_SHOCK_BOSS_3A) {
                    creature->type_id = CREATURE_TYPE_SPIDER_SP1;
                    creature->flags = CREATURE_FLAG_RANGED_ATTACK_SHOCK;
                    creature->orbit_angle = 0.9f;
                    creature->orbit_radius.projectile_type = PROJECTILE_TYPE_PLASMA_RIFLE;
                    creature->health = 4500.0f;
                    creature->move_speed = 2.0f;
                    creature->reward_value = 4500.0f;
                    child_tint.set(1.0f, 1.0f, 1.0f, 1.0f);
                    *(creature_tint_t *)&creature->color = child_tint;
                    creature->size = 64.0f;
                    creature->contact_damage = 50.0f;
                } else if (template_id == SPAWN_ID_SPIDER_SP1_CONST_BROWN_SMALL_3F) {
                    creature->type_id = CREATURE_TYPE_SPIDER_SP1;
                    creature->health = 200.0f;
                    child_tint.set(0.7f, 0.4f, 0.1f, 1.0f);
                    creature->move_speed = 2.3f;
                    creature->reward_value = 210.0f;
                    *(creature_tint_t *)&creature->color = child_tint;
                    creature->size = 35.0f;
                    creature->contact_damage = 20.0f;
                } else if (template_id == SPAWN_ID_SPIDER_SP1_CONST_BLUE_40) {
                    SET_ROOT_STATS_WITH_TINT(CREATURE_TYPE_SPIDER_SP1, 70.0f, 2.2f, 160.0f,
                                             0.5f, 0.6f, 0.9f, 1.0f, 45.0f, 5.0f);
                } else if (template_id == SPAWN_ID_ZOMBIE_CONST_GREY_42) {
                    SET_ROOT_STATS_WITH_TINT(CREATURE_TYPE_ZOMBIE, 200.0f, 1.7f, 160.0f,
                                             0.9f, 0.9f, 0.9f, 1.0f, 45.0f, 15.0f);
                } else if (template_id == SPAWN_ID_ZOMBIE_CONST_GREEN_BRUTE_43) {
                    SET_ROOT_STATS_WITH_TINT(CREATURE_TYPE_ZOMBIE, 2000.0f, 2.1f, 460.0f,
                                             0.2f, 0.6f, 0.1f, 1.0f, 70.0f, 15.0f);
                } else {
                    APPLY_UNHANDLED_TEMPLATE_FALLBACK();
                }

    if (!demo_mode_active
        && creature->position.x > 0.0f
        && (float)terrain_texture_width > creature->position.x
        && creature->position.y > 0.0f
        && (float)terrain_texture_height > creature->position.y) {
        effect_spawn_burst(
            &creature->position,
            8);
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
    if (!config_blob.hardcore
        && (creature->flags & CREATURE_FLAG_ANIM_PING_PONG) != 0) {
        creature_spawn_slot_t *spawn_slot =
            &creature_spawn_slot_table[creature->link_index];
        spawn_slot->interval_s = spawn_slot->interval_s + 0.2f;
    }

    if (config_blob.hardcore) {
        quest_fail_retry_count = 0;
        creature->move_speed = creature->move_speed * 1.05f;
        creature->contact_damage = creature->contact_damage * 1.4f;
        creature->health = creature->health * 1.2f;
        if ((creature->flags & CREATURE_FLAG_ANIM_PING_PONG) != 0) {
            creature_spawn_slot_t *spawn_slot =
                &creature_spawn_slot_table[creature->link_index];
            spawn_slot->interval_s = spawn_slot->interval_s - 0.2f;
            if (spawn_slot->interval_s < 0.1f) {
                spawn_slot->interval_s = 0.1f;
            }
        }
    } else if (quest_fail_retry_count > 0) {
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
            creature_spawn_slot_t *spawn_slot =
                &creature_spawn_slot_table[creature->link_index];
            if (retry_interval > 3.0f) {
                retry_interval = 3.0f;
            }
            spawn_slot->interval_s = spawn_slot->interval_s + retry_interval;
        }
    }

    return creature;
}

#undef APPLY_UNHANDLED_TEMPLATE_FALLBACK
#undef INIT_GRID_ROOT
#undef INIT_GRID_CHILD
#undef SPAWN_GRID
#undef SET_ROOT_STATS
#undef SET_ROOT_STATS_WITH_TINT
#undef INIT_ALIEN_SPAWNER
#undef RAND_FIELD
#undef RAND_FIELD_INT_BASE
#undef CLAMP_TINT_COMPONENT
#undef tint
#undef child_tint
#undef zero_velocity
#undef chain_position
#undef orbit_direction
