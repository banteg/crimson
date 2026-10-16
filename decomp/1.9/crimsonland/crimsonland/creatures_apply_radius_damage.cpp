#include <math.h>
#define creatures_apply_radius_damage creatures_apply_radius_damage_pointer_abi
#include "crimsonland_gameplay.h"
#undef creatures_apply_radius_damage

static __inline float vec2_distance(const vec2f_t *lhs, const vec2f_t *rhs)
{
    float dx = lhs->x - rhs->x;
    float dy = lhs->y - rhs->y;
    float distance_sq = dx * dx;
    float distance;
    distance_sq += dy * dy;
    distance = (float)sqrt(distance_sq);
    return distance;
}

extern "C" void creatures_apply_radius_damage(
    vec2f_t &spot,
    float radius,
    float damage,
    int damage_type)
{
    vec2f_t impulse = {0.0f, 0.0f};

    for (int creature_id = 0; creature_id < 0x180; ++creature_id) {
        if (creature_pool[creature_id].active
            && vec2_distance(
                   &creature_pool[creature_id].position,
                   &spot)
                    - radius
                < creature_pool[creature_id].size * 0.14285715f + 3.0f
            && creature_pool[creature_id].death_timer > 5.0f) {
            creature_apply_damage(
                creature_id,
                damage,
                damage_type,
                &impulse);
        }
    }
}
