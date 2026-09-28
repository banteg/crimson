#include "crimsonland_gameplay.h"

struct particle_scale_t {
    float x;
    float y;
    float z;
    float age;

    particle_scale_t(float x_value, float y_value, float z_value, float age_value)
        : x(x_value), y(y_value), z(z_value), age(age_value) {}
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
        *(particle_scale_t *)&entry->scale_x =
            particle_scale_t(1.0f, 1.0f, 1.0f, 1.0f);
        entry->spin = (float)(crt_rand() % 0x274) * 0.01f;
        entry->render_flag = 1;
        entry->target_id = -1;
        ++entry;
    } while (--remaining != 0);
}
