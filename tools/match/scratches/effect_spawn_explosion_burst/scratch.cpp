#include "crimsonland_gameplay.h"

static inline int explosion_debris_count(int detail)
{
    int count;
    if (detail < 2) {
        count = 1;
    } else {
        count = 3 + (detail >= 4);
    }
    return count;
}

extern "C" void effect_spawn_explosion_burst(
    const vec2f_t *pos,
    float scale)
{
    effect_color_t core_color = {0.6f, 0.6f, 0.6f, 1.0f};

    effect_template.flags = 0x19;
    effect_template.color = core_color;
    effect_template.lifetime = 0.35f;
    effect_template.age = -0.1f;
    effect_template.half_width = 32.0f;
    effect_template.half_height = 32.0f;
    effect_template.rotation = 0.0f;
    effect_template.vel_x = 0.0f;
    effect_template.vel_y = 0.0f;
    effect_template.scale_step = scale * 25.0f;
    effect_spawn(1, (float *)pos);

    effect_color_t shockwave_color = {0.1f, 0.1f, 0.1f, 1.0f};
    effect_template.flags = 0x5d;
    effect_template.color = shockwave_color;
    effect_template.rotation = 0.0f;
    effect_template.vel_x = 0.0f;
    effect_template.vel_y = 0.0f;

    if (config_blob.detail_preset > 3) {
        float shockwave_scale_step = scale * 5.0f;
        for (int index = 0; index < 2; ++index) {
            effect_template.half_width = 32.0f;
            effect_template.half_height = 32.0f;
            float time_offset = (float)index * 0.2f;
            effect_template.age = time_offset - 0.5f;
            effect_template.lifetime = time_offset + 0.6f;
            effect_template.rotation =
                (float)(crt_rand() % 614) * 0.02f;
            effect_template.rotation_step = 1.4f;
            effect_template.scale_step = shockwave_scale_step;
            effect_spawn(17, (float *)pos);
        }
    }

    effect_color_t flash_color = {1.0f, 1.0f, 1.0f, 1.0f};
    effect_template.flags = 0x19;
    effect_template.color = flash_color;
    effect_template.age = 0.0f;
    effect_template.lifetime = 0.3f;
    effect_template.half_width = 32.0f;
    effect_template.half_height = 32.0f;
    effect_template.rotation = 0.0f;
    effect_template.vel_x = 0.0f;
    effect_template.vel_y = 0.0f;
    effect_template.scale_step = scale * 45.0f;
    effect_spawn(0, (float *)pos);

    effect_color_t debris_color = {1.0f, 1.0f, 1.0f, 1.0f};
    effect_template.flags = 0x1d;
    effect_template.color = debris_color;
    effect_template.lifetime = 0.7f;
    effect_template.age = 0.0f;
    effect_template.half_width = 32.0f;
    effect_template.half_height = 32.0f;

    int detail = config_blob.detail_preset;
    int count = explosion_debris_count(detail);

    if (count > 0) {
        do {
            effect_template.rotation =
                (float)(crt_rand() % 314) * 0.02f;
            effect_template.vel_x =
                (float)((crt_rand() & 63) * 2 - 64);
            effect_template.vel_y =
                (float)((crt_rand() & 63) * 2 - 64);
            effect_template.scale_step =
                (float)((crt_rand() - 3) & 7) * scale;
            effect_template.rotation_step =
                (float)((crt_rand() + 3) & 7);
            effect_spawn(12, (float *)pos);
        } while (--count != 0);
    }
}
