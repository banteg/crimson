#include "grim2d_cpp.h"
#include "grim_texture.h"

extern unsigned char grim_render_disabled;

bool IGrim2D_cpp::grim_set_render_target(int target_index)
{
    if (grim_render_disabled) {
        return true;
    }

    if (target_index < 0) {
        if (grim_backbuffer_surface == 0) {
            return true;
        }

        if (grim_render_target_surface != 0) {
            grim_render_target_surface->Release();
        }
        grim_render_target_surface = 0;

        if (grim_d3d_device->SetRenderTarget(grim_backbuffer_surface, 0) < 0) {
            return false;
        }

        if (grim_backbuffer_surface != 0) {
            grim_backbuffer_surface->Release();
        }
        grim_backbuffer_surface = 0;
        return true;
    }

    if (grim_render_target_surface != 0) {
        grim_render_target_surface->Release();
        grim_render_target_surface = 0;
    }

    if (grim_backbuffer_surface == 0) {
        grim_d3d_device->GetRenderTarget(&grim_backbuffer_surface);
    }

    if (grim_texture_slots[target_index]->texture->GetSurfaceLevel(
            0, &grim_render_target_surface) < 0) {
        return false;
    }

    if (grim_d3d_device->SetRenderTarget(grim_render_target_surface, 0) < 0) {
        if (grim_render_target_surface != 0) {
            grim_render_target_surface->Release();
        }
        grim_render_target_surface = 0;
        return false;
    }

    return true;
}
