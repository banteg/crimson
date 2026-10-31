// crimson.exe 1.4.0, 0x40e6b0. Blood rotation and size are rolled during rendering.
#include "freeware_fx_queues.h"
extern "C" void fx_queue_add_random(const vec2f_t *pos) {
#define COUNT FX_STORE(freeware_blood_count, blood_count)
    FX_STORE(freeware_blood_positions, blood)[COUNT++] = *pos;
    if (COUNT >= 64)
        COUNT = 63;
}
