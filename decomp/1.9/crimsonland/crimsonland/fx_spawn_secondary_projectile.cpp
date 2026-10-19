#include "cl_build.h"
#if CL_BUILD < 10900
#define creature_find_nearest creature_find_nearest_19
#endif
#include "crimsonland_gameplay.h"
#if CL_BUILD < 10900
#undef creature_find_nearest
extern "C" int creature_find_nearest(const vec2f_t *pos);
#endif

extern "C" double cos(double angle);
extern "C" double sin(double angle);

#if CL_BUILD == 10300
extern "C" int secondary_projectile_alloc_slot(void);
#endif
extern "C" int fx_spawn_secondary_projectile(
    const vec2f_t *pos,
    float angle,
    secondary_projectile_type_id_t type_id
)
{
#if CL_BUILD == 10300
    int index = secondary_projectile_alloc_slot();
    float vel_x;
    float vel_y;
#elif CL_BUILD < 10900
    int index;
    float vel_x;
    float vel_y;
    for (index = 0; index < 0x40; index++) {
        if (!secondary_projectile_pool[index].active) {
            goto found;
        }
    }
    index = 0x3f;

found:
    ;
#else
    int index;
    float vel_x;
    float vel_y;
    secondary_projectile_t *projectile;
    for (index = 0; index < 0x40; index++) {
        if (!secondary_projectile_pool[index].active) {
            goto found;
        }
    }
    index = 0x3f;

found:
    ;
#endif
    ++highscore_record_shots_fired;

#if CL_BUILD < 10900
    secondary_projectile_pool[index].active = 1;
    secondary_projectile_pool[index].position = *pos;
    secondary_projectile_pool[index].life_timer = 2.0f;

    vel_x = (float)cos(angle - 1.57079637f);
    secondary_projectile_pool[index].fields.velocity.x = vel_x * 90.0f;

    vel_y = (float)sin(angle - 1.57079637f);
    secondary_projectile_pool[index].fields.velocity.y = vel_y * 90.0f;
    secondary_projectile_pool[index].angle = angle;
    secondary_projectile_pool[index].fields.trail_distance = 0.0f;
    secondary_projectile_pool[index].fields.type_id = type_id;

    if (type_id == SECONDARY_PROJECTILE_TYPE_SEEKER_ROCKET) {
#if CL_BUILD == 10300
        secondary_projectile_pool[index].fields.target_id =
            creature_find_nearest(
                (const vec2f_t *)((const char *)player_state_table + current_player_index * 0x148 + 0x4c));
#else
        secondary_projectile_pool[index].fields.target_id =
            creature_find_nearest(
                (const vec2f_t *)((const char *)player_state_table + current_player_index * 0x188 + 0x4c));
#endif
        secondary_projectile_pool[index].fields.velocity.x = vel_x * 190.0f;
        secondary_projectile_pool[index].fields.velocity.y = vel_y * 190.0f;
    }
#else
    projectile = &secondary_projectile_pool[index];
    projectile->active = 1;
    projectile->position = *pos;
    projectile->life_timer = 2.0f;

    vel_x = (float)cos(angle - 1.57079637f);
    projectile->fields.velocity.x = vel_x * 90.0f;

    vel_y = (float)sin(angle - 1.57079637f);
    projectile->fields.velocity.y = vel_y * 90.0f;
    projectile->angle = angle;
    projectile->fields.trail_distance = 0.0f;
    projectile->fields.type_id = type_id;

    if (type_id == SECONDARY_PROJECTILE_TYPE_SEEKER_ROCKET) {
        projectile->fields.target_id =
            creature_find_nearest(
                &player_state_table[current_player_index].aim,
                -1,
                0.0f);
        projectile->fields.velocity.x = vel_x * 190.0f;
        projectile->fields.velocity.y = vel_y * 190.0f;
    }
#endif

    return index;
}
