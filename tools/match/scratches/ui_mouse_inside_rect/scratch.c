#include "crimsonland_ui.h"

int ui_mouse_inside_rect(float *xy, int h, int w)
{
    if (ui_mouse_x > xy[0] &&
        ui_mouse_y > xy[1] &&
        xy[0] + w > ui_mouse_x &&
        xy[1] + h > ui_mouse_y &&
        !ui_mouse_blocked) {
        return 1;
    }

    return 0;
}
