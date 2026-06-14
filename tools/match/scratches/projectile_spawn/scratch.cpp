#include "crimsonland_gameplay.h"

extern "C" float cos(float angle);
extern "C" float sin(float angle);

extern "C" int projectile_spawn(float *pos, float angle, int type_id, int owner_id)
{
    float default_damage = 1.0f;

    if (!bonus_spawn_guard) {
        while (
            (owner_id == -100 || owner_id == -1 || owner_id == -2 || owner_id == -3)
            && (
                ++highscore_record_shots_fired,
                type_id != PROJECTILE_TYPE_FIRE_BULLETS
                    && (player_state_table[0].fire_bullets_timer > 0.0f
                        || player_state_table[1].fire_bullets_timer > 0.0f)
            )
        ) {
            type_id = PROJECTILE_TYPE_FIRE_BULLETS;
        }
    }

    int index = 0;
    projectile_t *projectile = projectile_pool;
    do {
        if (!projectile->active) {
            goto found;
        }
        ++projectile;
        ++index;
    } while ((int)projectile < (int)&projectile_pool[0x60]);
    index = 0x5f;

found:
    projectile = &projectile_pool[index];
    projectile->pos.tail.vy.owner_id = owner_id;
    projectile->active = 1;
    projectile->pos.tail.vy.travel_budget = weapon_table[type_id].travel_budget;
    projectile->pos_x = pos[0];
    projectile->pos.pos_y = pos[1];
    projectile->pos.origin_x = pos[0];
    projectile->pos.tail.origin_y = pos[1];
    projectile->angle = angle;
    projectile->pos.tail.vy.type_id = (projectile_type_id_t)type_id;
    projectile->pos.tail.vy.life_timer = 0.4f;
    projectile->pos.tail.vy.reserved = 0.0f;
    projectile->pos.tail.vy.speed_scale = 1.0f;
    projectile->pos.tail.vel_x = (float)(cos(angle) * 1.5f);
    projectile->pos.tail.vy.vel_y = (float)(sin(angle) * 1.5f);

    if (type_id == PROJECTILE_TYPE_ION_MINIGUN) {
        projectile->pos.tail.vy.hit_radius = 3.0f;
        projectile->pos.tail.vy.damage_pool = default_damage;
        return index;
    }
    if (type_id == PROJECTILE_TYPE_ION_RIFLE) {
        projectile->pos.tail.vy.hit_radius = 5.0f;
        projectile->pos.tail.vy.damage_pool = default_damage;
        return index;
    }
    if (type_id == PROJECTILE_TYPE_ION_CANNON || type_id == PROJECTILE_TYPE_PLASMA_CANNON) {
        projectile->pos.tail.vy.hit_radius = 10.0f;
    } else {
        projectile->pos.tail.vy.hit_radius = 1.0f;
        if (type_id == PROJECTILE_TYPE_GAUSS_GUN) {
            projectile->pos.tail.vy.damage_pool = 300.0f;
            return index;
        }
        if (type_id == PROJECTILE_TYPE_FIRE_BULLETS) {
            projectile->pos.tail.vy.damage_pool = 240.0f;
            return index;
        }
        if (type_id == PROJECTILE_TYPE_BLADE_GUN) {
            projectile->pos.tail.vy.damage_pool = 50.0f;
            return index;
        }
    }
    projectile->pos.tail.vy.damage_pool = default_damage;
    return index;
}
