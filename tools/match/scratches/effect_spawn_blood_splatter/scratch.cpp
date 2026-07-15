#include <math.h>

#include "crimsonland_gameplay.h"

extern "C" void effect_spawn_blood_splatter(
    float *pos,
    float angle,
    float age)
{
    if (config_violence_disabled != 0) {
        return;
    }

    effect_template.lifetime = 0.25f - age;
    effect_color_t color = {1.0f, 1.0f, 1.0f, 0.5f};
    double direction = angle + 3.14159274f;
    angle = (float)direction;
    float direction_cos = (float)cos(direction);

    effect_template.flags = 0xc9;
    effect_template.color = color;
    effect_template.scale_step = 0.0f;
    effect_template.age = age;

    float direction_sin = (float)sin(direction);
    int remaining = 2;
    do {
        effect_template.rotation =
            angle + (float)((crt_rand() & 63) - 32) * 0.1f;

        float half_extent = (float)((crt_rand() & 7) + 1);
        effect_template.half_width = half_extent;
        effect_template.half_height = half_extent;

        effect_template.vel_x =
            direction_cos * (float)((crt_rand() & 63) + 100);
        effect_template.vel_y =
            direction_sin * (float)((crt_rand() & 63) + 100);
        effect_template.rotation_step = 0.0f;
        effect_template.scale_step =
            (float)(crt_rand() & 127) * 0.03f + 0.1f;
        effect_spawn(7, pos);
    } while (--remaining != 0);
}
