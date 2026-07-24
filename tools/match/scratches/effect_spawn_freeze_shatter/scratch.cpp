#include <math.h>

#include "crimsonland_gameplay.h"

extern "C" void effect_spawn_freeze_shatter(
    const vec2f_t *pos,
    float angle)
{
    effect_color_t color = {1.0f, 1.0f, 1.0f, 0.5f};

    effect_template.flags = 0x5d;
    effect_template.color = color;
    effect_template.age = 0.0f;
    effect_template.lifetime = 1.1f;
    effect_template.scale_step = 0.0f;

    for (int index = 0; index < 4; ++index) {
        effect_template.rotation = angle + (float)index * 1.57079637f;
        effect_template.vel_x = (float)cos(effect_template.rotation) * 42.0f;
        effect_template.vel_y = (float)sin(effect_template.rotation) * 42.0f;

        float half_extent = (float)(crt_rand() % 10 + 18);
        effect_template.half_width = half_extent;
        effect_template.half_height = half_extent;
        effect_template.rotation_step =
            ((float)(crt_rand() % 20) * 0.1f - 1.0f) * 1.9f;
        effect_spawn(14, (float *)pos);
    }

    int remaining = 4;
    do {
        effect_spawn_freeze_shard(
            pos,
            (float)(crt_rand() % 612) * 0.01f);
    } while (--remaining != 0);
}
