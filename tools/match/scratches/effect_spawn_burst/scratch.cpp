#include "crimsonland_gameplay.h"

extern "C" void effect_spawn_burst(const vec2f_t *pos, int count)
{
    effect_color_t color = {0.4f, 0.5f, 1.0f, 0.5f};

    effect_template.flags = 0x1d;
    effect_template.color = color;
    effect_template.age = 0.0f;
    effect_template.lifetime = 0.5f;
    effect_template.half_extent.x = 32.0f;
    effect_template.half_extent.y = 32.0f;

    if (count > 0) {
        do {
            effect_template.rotation =
                (float)(crt_rand() & 0x7f) * 0.049087387f;
            effect_template.velocity.x = (float)((crt_rand() & 0x7f) - 64);
            effect_template.velocity.y = (float)((crt_rand() & 0x7f) - 64);
            effect_template.scale_step =
                (float)(crt_rand() % 100) * 0.01f + 0.1f;
            effect_spawn(0, pos);
        } while (--count != 0);
    }
}
