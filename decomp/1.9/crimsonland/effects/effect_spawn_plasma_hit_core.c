#include "crimsonland_gameplay.h"

void effect_spawn_plasma_hit_core(
    const vec2f_t *pos,
    float scale_step,
    float lifetime)
{
    effect_color_t color = {0.9f, 0.6f, 0.3f, 1.0f};

    effect_template.flags = 0x19;
    effect_template.color = color;
    effect_template.age = 0.1f;
    effect_template.lifetime = lifetime;
    effect_template.scale_step = scale_step * 45.0f;
    effect_template.half_width = 4.0f;
    effect_template.half_height = 4.0f;
    effect_template.rotation = 0.0f;
    effect_template.vel_x = 0.0f;
    effect_template.vel_y = 0.0f;
    effect_spawn(1, pos);
}
