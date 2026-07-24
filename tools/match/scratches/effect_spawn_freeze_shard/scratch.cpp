#include <math.h>

#include "crimsonland_gameplay.h"

extern "C" void effect_spawn_freeze_shard(
    const vec2f_t *pos,
    float angle)
{
    effect_color_t color = {1.0f, 1.0f, 1.0f, 0.5f};

    effect_template.flags = 0x1cd;
    effect_template.color = color;
    effect_template.lifetime =
        (float)(crt_rand() & 15) * 0.01f + 0.2f;
    effect_template.age = 0.0f;
    effect_template.half_width = 8.0f;
    effect_template.half_height = 8.0f;

    angle += 3.14159274f;
    effect_template.rotation =
        angle + (float)(crt_rand() % 100) * 0.01f;

    float half_extent = (float)(crt_rand() % 5 + 7);
    effect_template.half_width = half_extent;
    effect_template.half_height = half_extent;

    effect_template.vel_x = (float)cos(angle) * 114.0f;
    effect_template.vel_y = (float)sin(angle) * 114.0f;
    effect_template.rotation_step =
        ((float)(crt_rand() % 20) * 0.1f - 1.0f) * 4.0f;
    effect_template.scale_step =
        (float)-(crt_rand() & 15) * 0.1f;

    effect_spawn(crt_rand() % 3 + 8, pos);
}
