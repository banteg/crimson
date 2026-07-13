#include <math.h>

#include "crimsonland_gameplay.h"

void effect_spawn_splitter_hit_burst(float *pos, float radius, int count)
{
    effect_color_t color = {1.0f, 0.9f, 0.1f, 1.0f};

    effect_template.flags = 0x19;
    effect_template.color = color;
    effect_template.half_width = 4.0f;
    effect_template.half_height = 4.0f;
    effect_template.rotation = 0.0f;
    effect_template.vel_x = 0.0f;
    effect_template.vel_y = 0.0f;
    effect_template.scale_step = 55.0f;

    if (count > 0) {
        int radius_i = (int)radius;
        do {
            float angle = (float)(crt_rand() & 0x1ff) * 0.001953125f * 6.2831855f;
            float distance = (float)(crt_rand() % radius_i);
            float spawn_pos[2];

            spawn_pos[0] = (float)(cos(angle) * distance + pos[0]);
            spawn_pos[1] = (float)(sin(angle) * distance + pos[1]);
            effect_template.age = (float)-(crt_rand() & 0xff) * 0.0012f;
            effect_template.lifetime = 0.1f - effect_template.age;
            effect_spawn(0, spawn_pos);
        } while (--count != 0);
    }
}
