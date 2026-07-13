#include <math.h>
#include "crimsonland_gameplay.h"

int creature_find_in_radius(float *pos, float radius, int start_index)
{
    creature_t *creature;

    if (start_index < 0x180) {
        creature = &creature_pool[start_index];
        do {
            if (creature->active) {
                if ((float)sqrt(
                        (creature->pos_x - pos[0]) * (creature->pos_x - pos[0])
                        + (creature->pos_y - pos[1]) * (creature->pos_y - pos[1])
                    ) - radius < creature->size * 0.14285715f + 3.0f) {
                    if (creature->lifecycle_stage > 5.0f) {
                        return start_index;
                    }
                }
            }
            ++creature;
            ++start_index;
        } while ((int)creature < (int)&creature_pool[0x180]);
    }
    return -1;
}
