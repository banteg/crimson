#include "crimsonland_gameplay.h"

static inline int effect_detail_count(int count)
{
    if (config_blob.detail_preset < 3) {
        count /= 2;
    }
    return count;
}

extern "C" void effect_spawn_shrinkifier_hit(const vec2f_t *pos)
{
    effect_color_t core_color = {0.3f, 0.6f, 0.9f, 1.0f};

    effect_template.flags = 0x19;
    effect_template.color = core_color;
    effect_template.age = 0.0f;
    effect_template.lifetime = 0.3f;
    effect_template.half_extent.x = 36.0f;
    effect_template.half_extent.y = 36.0f;
    effect_template.rotation = 0.0f;
    effect_template.velocity.x = 0.0f;
    effect_template.velocity.y = 0.0f;
    effect_template.scale_step = -4.0f;
    effect_spawn(1, pos);

    effect_color_t debris_color = {0.4f, 0.5f, 1.0f, 0.5f};
    effect_template.flags = 0x1d;
    effect_template.color = debris_color;
    effect_template.age = 0.0f;
    effect_template.lifetime = 0.3f;
    effect_template.half_extent.x = 32.0f;
    effect_template.half_extent.y = 32.0f;

    int count = effect_detail_count(4);

    if (count > 0) {
        do {
            effect_template.rotation =
                (float)(crt_rand() & 127) * 0.0490873866f;
            effect_template.velocity.x =
                (float)((crt_rand() & 127) - 64) * 1.4f;
            effect_template.velocity.y =
                (float)((crt_rand() & 127) - 64) * 1.4f;
            effect_template.scale_step =
                (float)(crt_rand() % 100) * 0.01f + 0.1f;
            effect_spawn(0, pos);
        } while (--count != 0);
    }
}
