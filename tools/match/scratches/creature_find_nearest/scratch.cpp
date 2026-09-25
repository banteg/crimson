#include <math.h>
#include "crimsonland_gameplay.h"

static __inline float vec2_distance(const vec2f_t *lhs, const vec2f_t *rhs)
{
    float dx = lhs->x - rhs->x;
    float dy = lhs->y - rhs->y;
    float distance_sq = dx * dx;
    distance_sq += dy * dy;
    float distance = (float)sqrt(distance_sq);
    return distance;
}

extern "C" int creature_find_nearest(
    const vec2f_t *pos,
    int exclude_id,
    float min_dist)
{
    float best_distance = 1000000.0f;
    int best_index = 0;

    if (exclude_id == -1) {
        int index = 0;

        do {
            if (creature_pool[index].active
                && creature_pool[index].lifecycle_stage == 16.0f) {
                float distance = vec2_distance(
                    pos,
                    &creature_pool[index].position
                );
                if (distance < best_distance) {
                    best_index = index;
                    best_distance = distance;
                }
            }
            ++index;
        } while (index < 0x180);
        return best_index;
    }

    for (int index = 0; index < 0x180; index++) {
        if (creature_pool[index].active && index != exclude_id) {
            const vec2f_t *position = &creature_pool[index].position;
            float dx = pos->x - position->x;
            float dy = pos->y - position->y;
            double live_distance = sqrt(dx * dx + dy * dy);
            float distance = (float)live_distance;
            if ((float)live_distance > min_dist
                && distance < best_distance) {
                best_index = index;
                best_distance = distance;
            }
        }
    }
    return best_index;
}
