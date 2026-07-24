#include "crimsonland_gameplay.h"

int fx_spawn_sprite(
    const vec2f_t *pos,
    const vec2f_t *vel,
    float scale)
{
    int index = 0;
    sprite_effect_t *entry = &sprite_effect_pool[0];

    for (; (int)entry < (int)&sprite_effect_pool[0x180]; ++entry, ++index) {
        if (!entry->active) {
            goto allocated;
        }
    }
    index = crt_rand() % 0x180;

allocated:
    sprite_effect_pool[index].active = 1;
    sprite_effect_pool[index].color_b = 1.0f;
    sprite_effect_pool[index].color_g = 1.0f;
    sprite_effect_pool[index].color_r = 1.0f;
    sprite_effect_pool[index].color_a = 1.0f;
    sprite_effect_pool[index].pos_x = pos->x;
    sprite_effect_pool[index].pos_y = pos->y;
    sprite_effect_pool[index].vel_x = vel->x;
    sprite_effect_pool[index].vel_y = vel->y;
    sprite_effect_pool[index].scale = scale;
    sprite_effect_pool[index].rotation = (float)(crt_rand() % 0x274) * 0.01f;
    return index;
}
