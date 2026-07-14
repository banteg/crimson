#include "crimsonland_ui.h"

int ui_mouse_inside_rect_with_padding(float *xy, int h, int w)
{
    if (xy[0] - 10.0f < ui_mouse_x &&
        xy[1] - 2.0f < ui_mouse_y &&
        xy[0] + w > ui_mouse_x &&
        xy[1] + h > ui_mouse_y &&
        !ui_mouse_blocked) {
        return 1;
    }

    return 0;
}
