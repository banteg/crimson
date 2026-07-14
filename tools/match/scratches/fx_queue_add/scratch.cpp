#include "crimsonland_gameplay.h"

extern "C" unsigned char fx_queue_add(
    int effect_id,
    float *pos,
    float width,
    float height,
    float rotation,
    effect_color_t *color)
{
    int count = fx_queue_count;
    int offset = count * sizeof(fx_queue_entry_t);
    ++count;
    fx_queue_entry_t *entry = (fx_queue_entry_t *)((char *)fx_queue + offset);

    entry->pos_x = pos[0];
    entry->pos_y = pos[1];
    entry->color = *color;
    entry->width = width;
    entry->height = height;
    entry->rotation = rotation;
    entry->effect_id = effect_id;
    fx_queue_count = count;

    if (count >= 0x80) {
        fx_queue_count = 0x7f;
        return 0;
    }
    return 1;
}
