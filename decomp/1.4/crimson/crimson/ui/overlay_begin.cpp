// crimson.exe 1.4.0, 0x41efa0.
#include "overlay.h"
using namespace ui140;
extern "C" unsigned char freeware_overlay_begin() {
    filter(3);
    frame_dt = raw_delta() * .8f;
    if (UI_PENDING)
        reset_overlay_time();
    backdrop(freeware_simulation_clock - UI_SINCE, UI_SEE_THROUGH != 0);
    draw_backdrop();
    if (UI_ALPHA < 1)
        UI_ALPHA -= frame_dt * 2.4f;
    return 1;
}
