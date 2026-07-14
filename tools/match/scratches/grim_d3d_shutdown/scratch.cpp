#include "grim_texture.h"

void grim_d3d_shutdown(void)
{
    int i;
    GrimTexture *texture;

    if (grim_backbuffer_surface != 0) {
        if (grim_backbuffer_surface->Release() <= 0) {
            grim_backbuffer_surface = 0;
        }
    }
    if (grim_render_target_surface != 0) {
        if (grim_render_target_surface->Release() <= 0) {
            grim_render_target_surface = 0;
        }
    }
    if (grim_font_texture != 0) {
        if (grim_font_texture->Release() <= 0) {
            grim_font_texture = 0;
        }
    }
    if (grim_splash_texture != 0) {
        if (grim_splash_texture->Release() <= 0) {
            grim_splash_texture = 0;
        }
    }

    for (i = 0; i < 256; ++i) {
        texture = grim_texture_slots[i];
        delete texture;
        grim_texture_slots[i] = 0;
    }

    grim_release_geometry_buffers();

    if (grim_d3d_device != 0) {
        grim_d3d_device->Release();
    }
    grim_d3d_device = 0;

    if (grim_d3d8 != 0) {
        grim_d3d8->Release();
    }
    grim_d3d8 = 0;
}
