#include <math.h>
#include "crimsonland_gameplay.h"

static __inline float vec2_distance(const vec2f_t *lhs, const vec2f_t *rhs)
{
    float dx = lhs->x - rhs->x;
    float dy = lhs->y - rhs->y;
    return (float)sqrt(dx * dx + dy * dy);
}

extern "C" int plaguebearer_infection_count;

extern "C" int plaguebearer_spread_infection(int creature_id)
{
    int other_id;
    for (other_id = 0; other_id < 0x200; other_id++) {
        if (creature_pool[other_id].active && other_id != creature_id) {
            if (vec2_distance(
                    &creature_pool[other_id].position,
                    &creature_pool[creature_id].position
                ) < 45.0f) {
                goto found;
            }
        }
    }

    return 0;

found:
    if (plaguebearer_infection_count < 60) {
        if (creature_pool[other_id].plague_infected
            && creature_pool[creature_id].health < 150.0f) {
            creature_pool[creature_id].plague_infected = 1;
        }
        if (creature_pool[creature_id].plague_infected
            && creature_pool[other_id].health < 150.0f) {
            creature_pool[other_id].plague_infected = 1;
        }
    }
    return other_id;
}
