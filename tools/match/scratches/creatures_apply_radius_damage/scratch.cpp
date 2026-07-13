#include <math.h>
#include "crimsonland_gameplay.h"

extern "C" void creatures_apply_radius_damage(float *pos, float radius, float damage, int damage_type)
{
    float impulse[2];
    impulse[0] = 0.0f;
    impulse[1] = 0.0f;

    int creature_id = 0;
    do {
        creature_t *creature = &creature_pool[creature_id];
        if (creature->active) {
            if ((float)sqrt(
                    (creature->pos_x - pos[0]) * (creature->pos_x - pos[0])
                    + (creature->pos_y - pos[1]) * (creature->pos_y - pos[1])
                ) - radius < creature->size * 0.14285715f + 3.0f
                && creature->lifecycle_stage > 5.0f) {
                creature_apply_damage(creature_id, damage, damage_type, impulse);
            }
        }
        ++creature_id;
    } while (creature_id < 0x180);
}
