#include "crimsonland_gameplay.h"

extern "C" unsigned char fx_queue_add(
    int effect_id,
    vec2f_t *pos,
    float width,
    float height,
    float rotation,
    effect_color_t *color)
{
    fx_queue[fx_queue_count].position = *pos;
    fx_queue[fx_queue_count].color = *color;
    fx_queue[fx_queue_count].width = width;
    fx_queue[fx_queue_count].height = height;
    fx_queue[fx_queue_count].rotation = rotation;
    fx_queue[fx_queue_count++].effect_id = effect_id;

    if (fx_queue_count >= 0x80) {
        fx_queue_count = 0x7f;
        return 0;
    }
    return 1;
}
