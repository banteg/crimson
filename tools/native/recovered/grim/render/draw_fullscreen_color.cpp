#include "grim_d3d8.h"
#include "grim2d_cpp.h"

extern IDirect3DDevice8 *grim_d3d_device;
extern unsigned int grim_backbuffer_width;
extern unsigned int grim_backbuffer_height;

void IGrim2D_cpp::grim_draw_fullscreen_color(
    float r, float g, float b, float a)
{
    if (a > 0.0f) {
        grim_d3d_device->SetTexture(0, 0);
        grim_d3d_device->SetTextureStageState(
            0, D3DTSS_COLOROP, D3DTOP_SELECTARG2);
        grim_d3d_device->SetTextureStageState(
            0, D3DTSS_ALPHAOP, D3DTOP_SELECTARG2);

        grim_set_color(r, g, b, a);
        grim_set_rotation(0.0f);
        grim_begin_batch();
        grim_draw_quad(
            0.0f,
            0.0f,
            (float)grim_backbuffer_width,
            (float)grim_backbuffer_height);
        grim_end_batch();

        grim_d3d_device->SetTextureStageState(
            0, D3DTSS_COLOROP, D3DTOP_MODULATE);
        grim_d3d_device->SetTextureStageState(
            0, D3DTSS_ALPHAOP, D3DTOP_MODULATE);
    }
}
