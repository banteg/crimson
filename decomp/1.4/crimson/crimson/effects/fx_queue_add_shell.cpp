// crimson.exe 1.4.0, 0x40e6f0.
#include "freeware_fx_queues.h"
extern "C" void fx_queue_add_shell(const vec2f_t *pos) {
#ifdef CRIMSON_FREEWARE_CLIENT
    if (!freeware_frame_game->shell_marks)
        return;
#else
    if (!freeware_shell_marks)
        return;
#endif
#define COUNT FX_STORE(freeware_shell_count, shell_count)
    FX_STORE(freeware_shell_positions, shells)[COUNT++] = *pos;
    if (COUNT >= 32)
        COUNT = 31;
}
