#include "cl_build.h"
#include "crimsonland_gameplay.h"

extern "C" int fx_spawn_sprite(
    const vec2f_t *pos,
    const vec2f_t *vel,
    float scale)
{
    int index;
    for (index = 0; index < 0x180; index++) {
        if (!sprite_effect_pool[index].active) {
            goto allocated;
        }
    }
#if CL_BUILD <= 10908
    // 1.9.8 recycles only the upper 256 slots.
    index = crt_rand() % 0x100 + 0x80;
#else
    index = crt_rand() % 0x180;
#endif

allocated:
    ;
    sprite_effect_pool[index].active = 1;
    sprite_effect_pool[index].color_b = 1.0f;
    sprite_effect_pool[index].color_g = 1.0f;
    sprite_effect_pool[index].color_r = 1.0f;
    sprite_effect_pool[index].color_a = 1.0f;
    sprite_effect_pool[index].position = *pos;
    sprite_effect_pool[index].velocity = *vel;
    sprite_effect_pool[index].scale = scale;
    sprite_effect_pool[index].rotation = (float)(crt_rand() % 0x274) * 0.01f;
    return index;
}
