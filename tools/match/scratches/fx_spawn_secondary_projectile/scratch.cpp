#include "crimsonland_gameplay.h"

extern "C" double cos(double angle);
extern "C" double sin(double angle);

extern "C" int fx_spawn_secondary_projectile(
    const vec2f_t *pos,
    float angle,
    secondary_projectile_type_id_t type_id
)
{
    int index = 0;
    float vel_x;
    float vel_y;
    secondary_projectile_t *projectile = secondary_projectile_pool;
    while ((int)projectile < (int)&secondary_projectile_pool[0x40]) {
        if (!projectile->active) {
            goto found;
        }
        ++projectile;
        ++index;
    }
    index = 0x3f;

found:
    ++highscore_record_shots_fired;

    projectile = &secondary_projectile_pool[index];
    projectile->active = 1;
    projectile->position = *pos;
    projectile->life_timer = 2.0f;

    vel_x = (float)cos(angle - 1.57079637f);
    projectile->pos.vx.vel_x = vel_x * 90.0f;

    vel_y = (float)sin(angle - 1.57079637f);
    projectile->pos.vx.vy.vel_y = vel_y * 90.0f;
    projectile->angle = angle;
    projectile->pos.vx.vy.trail_timer = 0.0f;
    projectile->pos.vx.vy.type_id = type_id;

    if (type_id == SECONDARY_PROJECTILE_TYPE_SEEKER_ROCKET) {
        projectile->pos.vx.vy.target_id =
            creature_find_nearest(
                &player_state_table[render_overlay_player_index].aim,
                -1,
                0.0f);
        projectile->pos.vx.vel_x = vel_x * 190.0f;
        projectile->pos.vx.vy.vel_y = vel_y * 190.0f;
    }

    return index;
}
