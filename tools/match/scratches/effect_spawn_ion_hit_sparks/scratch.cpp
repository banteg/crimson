#include "crimsonland_gameplay.h"

static inline int effect_detail_count(int count)
{
    if (config_blob.detail_preset < 3) {
        count /= 2;
    }
    return count;
}

extern "C" void effect_spawn_ion_hit_sparks(
    const vec2f_t *pos,
    float scale)
{
    scale *= 0.8f;
    effect_color_t color = {0.4f, 0.5f, 1.0f, 0.5f};

    effect_template.flags = 0x1d;
    effect_template.color = color;
    float lifetime = scale * 0.7f;
    effect_template.lifetime = lifetime;
    effect_template.age = 0.0f;
    if (lifetime > 1.1f) {
        effect_template.lifetime = 1.1f;
    }

    effect_template.half_extent.x = scale * 32.0f;
    effect_template.half_extent.y = scale * 32.0f;

    int count = effect_detail_count((int)(scale * 5.0f));
    if (count <= 0) {
        return;
    }

    int remaining = count;
    do {
        effect_template.rotation =
            (float)(crt_rand() & 127) * 0.0490873866f;
        effect_template.velocity.x =
            (float)((crt_rand() & 127) - 64) * scale * 1.4f;
        effect_template.velocity.y =
            (float)((crt_rand() & 127) - 64) * scale * 1.4f;
        effect_template.scale_step =
            ((float)(crt_rand() % 100) * 0.01f + 0.1f) * scale;
        effect_spawn(0, pos);
    } while (--remaining != 0);
}
