#include "crimsonland_gameplay.h"

extern "C" float cos(float angle);
extern "C" float sin(float angle);

extern "C" int fx_spawn_secondary_projectile(float *pos, float angle, int type_id)
{
    int index = 0;
    secondary_projectile_t *projectile = secondary_projectile_pool;
    do {
        if (!projectile->active) {
            goto found;
        }
        ++projectile;
        ++index;
    } while ((int)projectile < (int)&secondary_projectile_pool[0x40]);
    index = 0x3f;

found:
    float shot_angle = angle - 1.57079637f;
    ++highscore_record_shots_fired;

    projectile = &secondary_projectile_pool[index];
    projectile->active = 1;
    projectile->pos_x = pos[0];
    projectile->pos.pos_y = pos[1];
    projectile->life_timer = 2.0f;
    projectile->angle = angle;
    projectile->pos.vx.vy.trail_timer = 0.0f;
    projectile->pos.vx.vy.type_id = (secondary_projectile_type_id_t)type_id;

    float vel_x = (float)cos(shot_angle);
    projectile->pos.vx.vel_x = vel_x * 90.0f;

    float vel_y = (float)sin(shot_angle);
    projectile->pos.vx.vy.vel_y = vel_y * 90.0f;

    if (type_id == SECONDARY_PROJECTILE_TYPE_SEEKER_ROCKET) {
        projectile->pos.vx.vy.target_id =
            creature_find_nearest(&player_state_table[render_overlay_player_index].aim_x, -1, 0.0f);
        projectile->pos.vx.vel_x = vel_x * 190.0f;
        projectile->pos.vx.vy.vel_y = vel_y * 190.0f;
    }

    return index;
}
