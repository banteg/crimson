#include <string.h>
#include "cl_build.h"
#define projectile_spawn projectile_spawn_19
#include "crimsonland_gameplay.h"
#undef projectile_spawn
extern "C" double cos(double angle);
extern "C" double sin(double angle);
#if CL_BUILD >= 10300
extern "C" float bonus_fire_bullets_timer;
#endif
#if CL_BUILD < 10400
extern "C" int projectile_alloc_slot(void);
#endif

extern "C" int projectile_spawn(
    const vec2f_t *pos,
    float angle,
    int type_id)
{
#if CL_BUILD < 10400
    int index = projectile_alloc_slot();
#else
    int index;
    for (index = 0; index < PROJECTILE_POOL_CAPACITY; index++) {
        if (!projectile_pool[index].active) {
            goto found;
        }
    }
    index = PROJECTILE_POOL_CAPACITY - 1;
found:
    ;
#endif
#if CL_BUILD >= 10300
    ++highscore_record_shots_fired;
#endif
    projectile_pool[index].active = 1;
    projectile_pool[index].position = *pos;
    projectile_pool[index].fields.origin = *pos;
    projectile_pool[index].angle = angle;
    projectile_pool[index].fields.type_id = (projectile_type_id_t)type_id;
    projectile_pool[index].fields.velocity.x = (float)cos(angle + 0.78539819f) * 2.0f;
    projectile_pool[index].fields.velocity.y = (float)sin(angle + 0.78539819f) * 2.0f;
    projectile_pool[index].fields.life_timer = 0.4f;
    projectile_pool[index].fields.reserved = 1.0f;
    projectile_pool[index].fields.speed_scale = 1.0f;
#if CL_BUILD >= 10300
    if (type_id == 10) {
        projectile_pool[index].fields.damage_pool = 300.0f;
        return index;
    }
    if (bonus_fire_bullets_timer > 0.0f) {
        projectile_pool[index].fields.damage_pool = 240.0f;
        return index;
    }
    projectile_pool[index].fields.damage_pool = 1.0f;
#endif
    return index;
}
