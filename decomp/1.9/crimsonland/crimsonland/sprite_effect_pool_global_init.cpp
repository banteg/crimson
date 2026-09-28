#include "crimsonland_gameplay.h"

struct sprite_color_t {
    float r;
    float g;
    float b;
    float a;

    sprite_color_t(float r_value, float g_value, float b_value, float a_value)
        : r(r_value), g(g_value), b(b_value), a(a_value) {}
};

extern "C" void sprite_effect_pool_global_init(void)
{
    int remaining = 0x180;
    sprite_effect_t *entry = sprite_effect_pool;

    do {
        entry->active = 0;
        *(sprite_color_t *)&entry->color =
            sprite_color_t(1.0f, 1.0f, 1.0f, 1.0f);
        ++entry;
    } while (--remaining != 0);
}
