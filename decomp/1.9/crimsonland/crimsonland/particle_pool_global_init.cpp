#include "crimsonland_gameplay.h"

struct particle_color_t {
    float r;
    float g;
    float b;
    float a;

    particle_color_t(float r_value, float g_value, float b_value, float a_value)
        : r(r_value), g(g_value), b(b_value), a(a_value) {}
};

extern "C" int crt_rand(void);

extern "C" void particle_pool_global_init(void)
{
    int remaining = 0x80;
    particle_t *entry = particle_pool;

    do {
        entry->style_id = 0;
        entry->active = 0;
        entry->intensity = 1.0f;
        *(particle_color_t *)&entry->color_r =
            particle_color_t(1.0f, 1.0f, 1.0f, 1.0f);
        entry->rotation = (float)(crt_rand() % 0x274) * 0.01f;
        entry->in_flight = 1;
        entry->target_id = -1;
        ++entry;
    } while (--remaining != 0);
}
