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

extern "C" int player_find_in_radius(
    int owner_id,
    const vec2f_t *pos,
    float radius)
{
    int skip_index = -1 - owner_id;
    int player_index = 0;

    while (player_index < config_blob.player_count) {
        if (player_index != skip_index
            && player_state_table[player_index].health > 0.0f
            && vec2_distance(
                    &player_state_table[player_index].position,
                    pos)
                    - radius
                < player_state_table[player_index].size * 0.14285715f + 3.0f) {
            goto found;
        }
        ++player_index;
    }

    return -1;

found:
    return player_index;
}
