#include "crimsonland_gameplay.h"

extern "C" float cos(float angle);
extern "C" float sin(float angle);

typedef struct particle_scale_t {
    float scale_x;
    float scale_y;
    float scale_z;
    float age;
} particle_scale_t;

extern "C" int fx_spawn_particle(
    const vec2f_t *pos,
    float angle,
    const vec2f_t *,
    float intensity)
{
    particle_scale_t scale;
    int index = 0;
    particle_t *particle = particle_pool;
    while ((int)particle < (int)&particle_pool[0x80]) {
        if (!particle->active) {
            goto found;
        }
        ++particle;
        ++index;
    }
    index = crt_rand() % 0x80;

found:
    scale.scale_x = 1.0f;
    scale.scale_y = 1.0f;
    scale.scale_z = 1.0f;
    scale.age = 0.0f;

    particle_pool[index].active = 1;
    particle_pool[index].position = *pos;
    particle_pool[index].vel_x = (float)cos(angle) * 90.0f;
    particle_pool[index].vel_y = (float)sin(angle) * 90.0f;
    particle_pool[index].intensity = intensity;
    *(particle_scale_t *)&particle_pool[index].scale_x = scale;
    particle_pool[index].angle = angle;
    particle_pool[index].spin = (float)(crt_rand() % 0x274) * 0.01f;
    particle_pool[index].render_flag = 1;
    *(unsigned char *)&particle_pool[index].style_id = 0;

    return index;
}
