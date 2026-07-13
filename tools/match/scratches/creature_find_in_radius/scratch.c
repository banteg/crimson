#include <math.h>
#include "crimsonland_gameplay.h"

int creature_find_in_radius(float *pos, float radius, int start_index)
{
    int index = start_index;

    if (index < 0x180) {
        do {
            creature_t *creature = &creature_pool[index];
            if (creature->active) {
                float dx = creature->pos_x - pos[0];
                float dy = creature->pos_y - pos[1];
                float distance = (float)sqrt(dx * dx + dy * dy);
                if (distance - radius < creature->size * 0.14285715f + 3.0f) {
                    if (creature->lifecycle_stage > 5.0f) {
                        return index;
                    }
                }
            }
            ++index;
        } while (index < 0x180);
    }
    return -1;
}
