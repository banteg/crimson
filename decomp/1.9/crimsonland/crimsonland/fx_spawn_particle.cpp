#include "crimsonland_gameplay.h"

extern "C" float cos(float angle);
extern "C" float sin(float angle);

typedef struct particle_color_t {
    float color_r;
    float color_g;
    float color_b;
    float color_a;
} particle_color_t;

extern "C" int fx_spawn_particle(
    const vec2f_t *pos,
    float angle,
    const vec2f_t *,
    float intensity)
{
    particle_color_t color;
    int index;
    for (index = 0; index < 0x80; index++) {
        if (!particle_pool[index].active) {
            goto found;
        }
    }
    index = crt_rand() % 0x80;

found:
    color.color_r = 1.0f;
    color.color_g = 1.0f;
    color.color_b = 1.0f;
    color.color_a = 0.0f;

    particle_pool[index].active = 1;
    particle_pool[index].position = *pos;
    particle_pool[index].velocity.x = (float)cos(angle) * 90.0f;
    particle_pool[index].velocity.y = (float)sin(angle) * 90.0f;
    particle_pool[index].intensity = intensity;
    *(particle_color_t *)&particle_pool[index].color_r = color;
    particle_pool[index].angle = angle;
    particle_pool[index].rotation = (float)(crt_rand() % 0x274) * 0.01f;
    particle_pool[index].in_flight = 1;
    particle_pool[index].style_id = 0;

    return index;
}
