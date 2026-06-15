#include <math.h>
#include "crimsonland_gameplay.h"

extern "C" void creatures_apply_radius_damage(float *pos, float radius, float damage, int damage_type)
{
    float impulse[2];
    impulse[0] = 0.0f;
    impulse[1] = 0.0f;

    int creature_id = 0;
    creature_t *creature = creature_pool;
    do {
        if (creature->active) {
            float dx = creature->pos_x - pos[0];
            float dy = creature->pos_y - pos[1];
            if ((float)sqrt(dx * dx + dy * dy) - radius < creature->size * 0.14285715f + 3.0f
                && creature->hitbox_size > 5.0f) {
                creature_apply_damage(creature_id, damage, damage_type, impulse);
            }
        }
        ++creature;
        ++creature_id;
    } while ((int)creature < (int)&creature_pool[0x180]);
}
