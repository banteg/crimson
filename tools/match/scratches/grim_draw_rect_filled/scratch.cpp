// Wine's D3D8 headers use post-VC6 Win32 aliases that are absent from the
// compiler's bundled platform SDK.
typedef int WINBOOL;
typedef void *HMONITOR;

#include <d3d8.h>

#include "grim2d_cpp.h"

extern IDirect3DDevice8 *grim_d3d_device;

void IGrim2D_cpp::grim_draw_rect_filled(
    float *xy, float width, float height, float *rgba)
{
    if (rgba[3] > 0.0f) {
        grim_d3d_device->SetTexture(0, 0);
        grim_d3d_device->SetTextureStageState(
            0, D3DTSS_COLOROP, D3DTOP_SELECTARG2);
        grim_d3d_device->SetTextureStageState(
            0, D3DTSS_ALPHAOP, D3DTOP_SELECTARG2);

        grim_set_color_ptr(rgba);
        grim_set_rotation(0.0f);
        grim_begin_batch();
        grim_draw_quad(xy[0], xy[1], width, height);
        grim_end_batch();

        grim_d3d_device->SetTextureStageState(
            0, D3DTSS_COLOROP, D3DTOP_MODULATE);
        grim_d3d_device->SetTextureStageState(
            0, D3DTSS_ALPHAOP, D3DTOP_MODULATE);
    }
}
