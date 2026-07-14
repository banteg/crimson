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

int creature_find_in_radius(float *pos, float radius, int start_index)
{
    int index = start_index;

    while (index < 0x180) {
        if (creature_pool[index].active
            && vec2_distance((vec2f_t *)&creature_pool[index].pos_x, (vec2f_t *)pos) - radius
                < creature_pool[index].size * 0.14285715f + 3.0f
            && creature_pool[index].lifecycle_stage > 5.0f) {
            goto found;
        }
        ++index;
    }
    return -1;

found:
    return index;
}
