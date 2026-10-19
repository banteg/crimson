#include "cl_build.h"
#define fx_queue_add fx_queue_add_19
#include "crimsonland_gameplay.h"
#undef fx_queue_add
extern "C" void fx_queue_add(
    int effect_id,
    vec2f_t *pos,
    float width,
    float height,
    float rotation,
    effect_color_t color)
{
    fx_queue[fx_queue_count].position = *pos;
    fx_queue[fx_queue_count].color = color;
    fx_queue[fx_queue_count].width = width;
    fx_queue[fx_queue_count].height = height;
    fx_queue[fx_queue_count].rotation = rotation;
    fx_queue[fx_queue_count++].effect_id = effect_id;

    if (fx_queue_count >= 0x40) {
        fx_queue_count = 0x3f;
    }
}
