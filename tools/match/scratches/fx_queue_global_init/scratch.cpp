#include "crimsonland_gameplay.h"

struct fx_vec2_t {
    float x;
    float y;

    fx_vec2_t(float x_value, float y_value)
        : x(x_value), y(y_value) {}
};

struct fx_color_t {
    float r;
    float g;
    float b;
    float a;

    fx_color_t(float r_value, float g_value, float b_value, float a_value)
        : r(r_value), g(g_value), b(b_value), a(a_value) {}
};

extern "C" void fx_queue_global_init(void)
{
    int remaining = 128;
    fx_queue_entry_t *entry = fx_queue;

    do {
        entry->effect_id = 0;
        entry->rotation = 0.0f;
        *(fx_vec2_t *)&entry->position = fx_vec2_t(0.0f, 0.0f);
        entry->height = 0.0f;
        entry->width = 0.0f;
        *(fx_color_t *)&entry->color =
            fx_color_t(1.0f, 1.0f, 1.0f, 1.0f);
        ++entry;
    } while (--remaining != 0);
}
