#include <math.h>
#include "crimsonland_gameplay.h"

static __inline float vec2_distance(const vec2f_t *lhs, const vec2f_t *rhs)
{
    float dx = lhs->x - rhs->x;
    float dy = lhs->y - rhs->y;
    float distance_sq = dx * dx;
    distance_sq += dy * dy;
    return (float)sqrt(distance_sq);
}

extern "C" void creatures_apply_radius_damage(float *pos, float radius, float damage, int damage_type)
{
    float impulse[2];
    impulse[0] = 0.0f;
    impulse[1] = 0.0f;

    int creature_id = 0;
    do {
        creature_t &creature = creature_pool[creature_id];
        if (creature.active
            && vec2_distance((vec2f_t *)&creature.pos_x, (vec2f_t *)pos) - radius
                < creature.size * 0.14285715f + 3.0f
            && creature.lifecycle_stage > 5.0f) {
            creature_apply_damage(creature_id, damage, damage_type, impulse);
        }
        ++creature_id;
    } while (creature_id < 0x180);
}
