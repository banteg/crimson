#include <math.h>
#include "crimsonland_types.h"

extern "C" creature_t creature_pool[512];

static __inline float distance_to(const vec2f_t *pos, const vec2f_t *target)
{
    float dx = pos->x - target->x;
    float dy = pos->y - target->y;
    float squared = dx * dx;
    squared += dy * dy;
    return (float)sqrt(squared);
}

extern "C" int creature_find_nearest(const vec2f_t *pos)
{
    int nearest = 0;
    float best = 100000000.0f;
    for (int i = 0; i < 512; ++i) {
        if (creature_pool[i].active) {
            float distance = distance_to(pos, &creature_pool[i].position);
            if (distance < best) {
                best = distance;
                nearest = i;
            }
        }
    }
    return nearest;
}
