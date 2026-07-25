#include "crimsonland_gameplay.h"

extern "C" float cos(float angle);
extern "C" float sin(float angle);

extern "C" int projectile_spawn(
    const vec2f_t *pos,
    float angle,
    int type_id,
    int owner_id)
{
    float default_damage = 1.0f;
    int index;
    int result;
    projectile_t *projectile;
    projectile_t *spawned;

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

    index = 0;
    projectile = projectile_pool;
    while ((int)projectile < (int)&projectile_pool[0x60]) {
        if (!projectile->active) {
            result = index;
            goto initialize;
        }
        ++projectile;
        ++index;
    }
    result = 0x5f;

initialize:
    spawned = &projectile_pool[result];
    spawned->pos.tail.vy.owner_id = owner_id;
    spawned->active = 1;
    spawned->pos.tail.vy.travel_budget = weapon_table[type_id].travel_budget;
    spawned->position = *pos;
    spawned->pos.origin = *pos;
    spawned->angle = angle;
    spawned->pos.tail.vy.type_id = (projectile_type_id_t)type_id;
    spawned->pos.tail.vy.life_timer = 0.4f;
    spawned->pos.tail.vy.reserved = 0.0f;
    spawned->pos.tail.vy.speed_scale = 1.0f;
    spawned->pos.tail.vel_x = (float)(cos(angle) * 1.5f);
    spawned->pos.tail.vy.vel_y = (float)(sin(angle) * 1.5f);

    if (type_id == PROJECTILE_TYPE_ION_MINIGUN) {
        spawned->pos.tail.vy.hit_radius = 3.0f;
        spawned->pos.tail.vy.damage_pool = default_damage;
        return result;
    }
    if (type_id == PROJECTILE_TYPE_ION_RIFLE) {
        spawned->pos.tail.vy.hit_radius = 5.0f;
        spawned->pos.tail.vy.damage_pool = default_damage;
        return result;
    }
    if (type_id == PROJECTILE_TYPE_ION_CANNON || type_id == PROJECTILE_TYPE_PLASMA_CANNON) {
        spawned->pos.tail.vy.hit_radius = 10.0f;
    } else {
        spawned->pos.tail.vy.hit_radius = 1.0f;
        if (type_id == PROJECTILE_TYPE_GAUSS_GUN) {
            spawned->pos.tail.vy.damage_pool = 300.0f;
            return result;
        }
        if (type_id == PROJECTILE_TYPE_FIRE_BULLETS) {
            spawned->pos.tail.vy.damage_pool = 240.0f;
            return result;
        }
        if (type_id == PROJECTILE_TYPE_BLADE_GUN) {
            spawned->pos.tail.vy.damage_pool = 50.0f;
            return result;
        }
    }
    spawned->pos.tail.vy.damage_pool = default_damage;
    return result;
}
