#include "grim_d3d8.h"
#include "grim2d_cpp.h"

extern IDirect3DDevice8 *grim_d3d_device;

void IGrim2D_cpp::grim_draw_rect_outline(
    float *xy, float width, float height)
{
    grim_d3d_device->SetTexture(0, 0);
    grim_d3d_device->SetTextureStageState(
        0, D3DTSS_COLOROP, D3DTOP_SELECTARG2);
    grim_d3d_device->SetTextureStageState(
        0, D3DTSS_ALPHAOP, D3DTOP_SELECTARG2);

    grim_set_rotation(0.0f);
    grim_begin_batch();
    if (height == 1.0f) {
        grim_draw_quad(xy[0], xy[1], width, 1.0f);
    } else if (width == 1.0f) {
        grim_draw_quad(xy[0], xy[1], 1.0f, height);
    } else {
        grim_draw_quad(xy[0], xy[1], width, 1.0f);
        grim_draw_quad(xy[0], xy[1], 1.0f, height);
        grim_draw_quad(xy[0], xy[1] + height, width + 1.0f, 1.0f);
        grim_draw_quad(xy[0] + width, xy[1], 1.0f, height);
    }
    grim_end_batch();

    grim_d3d_device->SetTextureStageState(
        0, D3DTSS_COLOROP, D3DTOP_MODULATE);
    grim_d3d_device->SetTextureStageState(
        0, D3DTSS_ALPHAOP, D3DTOP_MODULATE);
}
