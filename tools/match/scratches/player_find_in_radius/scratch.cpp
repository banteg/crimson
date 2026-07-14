#include <math.h>
#include "crimsonland_gameplay.h"

extern "C" int player_find_in_radius(int owner_id, float *pos, float radius)
{
    int skip_index = -1 - owner_id;
    int player_index = 0;

    if (config_blob.player_count > 0) {
        float *health = &player_state_table[0].health;
        do {
            if (player_index != skip_index && *health > 0.0f) {
                float dx = health[-4] - pos[0];
                float dy = health[-3] - pos[1];
                float distance_sq = dx * dx;
                distance_sq += dy * dy;
                if ((float)sqrt(distance_sq) - radius
                    < health[4] * 0.14285715f + 3.0f) {
                    return player_index;
                }
            }
            ++player_index;
            health += sizeof(player_state_t) / sizeof(float);
        } while (player_index < config_blob.player_count);
    }

    return -1;
}
