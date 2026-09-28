#include "grim2d_cpp.h"
#include "grim_texture.h"

extern unsigned char grim_render_disabled;
extern unsigned char grim_device_ready;

void IGrim2D_cpp::grim_clear_color(float r, float g, float b, float a)
{
    if (grim_render_disabled) {
        return;
    }
    if (!grim_device_ready) {
        return;
    }

    grim_d3d_device->Clear(
        0,
        0,
        D3DCLEAR_TARGET,
        D3DCOLOR_COLORVALUE(r, g, b, a),
        0.0f,
        0);
}
