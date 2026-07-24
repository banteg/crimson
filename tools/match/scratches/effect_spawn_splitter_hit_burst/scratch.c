#include <math.h>

#include "crimsonland_gameplay.h"

void effect_spawn_splitter_hit_burst(
    const vec2f_t *pos,
    float radius,
    int count)
{
    effect_color_t color = {1.0f, 0.9f, 0.1f, 1.0f};
    int remaining = count;

    effect_template.flags = 0x19;
    effect_template.color = color;
    effect_template.half_width = 4.0f;
    effect_template.half_height = 4.0f;
    effect_template.rotation = 0.0f;
    effect_template.vel_x = 0.0f;
    effect_template.vel_y = 0.0f;
    effect_template.scale_step = 55.0f;

    if (remaining > 0) {
        int radius_i = (int)radius;
        do {
            float angle = (float)(crt_rand() & 0x1ff);
            double distance;
            vec2f_t spawn_pos;

            angle *= 0.001953125f;
            angle *= 6.2831855f;
            distance = crt_rand() % radius_i;
            spawn_pos.x = (float)(cos(angle) * distance + pos->x);
            spawn_pos.y = (float)(sin(angle) * distance + pos->y);
            effect_template.age = (float)-(crt_rand() & 0xff) * 0.0012f;
            effect_template.lifetime = 0.1f - effect_template.age;
            effect_spawn(0, &spawn_pos);
        } while (--remaining != 0);
    }
}
