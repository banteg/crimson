// crimson.exe 1.4.0, 0x405c80.
#include "freeware_fx_queues.h"
#include "freeware_edition.h"
extern "C" void fx_queue_add(FreewareFxTexture texture, const vec2f_t *pos, float width, float height,
                             float rotation, effect_color_t color) {
#define QUEUE FX_STORE(fx_queue, impacts)
#define COUNT FX_STORE(fx_queue_count, impact_count)
    QUEUE[COUNT].position = *pos;
    QUEUE[COUNT].color = color;
    QUEUE[COUNT].width = width;
    QUEUE[COUNT].height = height;
    QUEUE[COUNT].rotation = rotation;
    QUEUE[COUNT++].effect_id = texture;
    const int capacity = FREEWARE_EDITION == 10300 ? 32 : 64;
    if (COUNT >= capacity)
        COUNT = capacity - 1;
}
