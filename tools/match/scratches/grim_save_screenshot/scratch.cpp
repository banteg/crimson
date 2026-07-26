#include "grim2d_cpp.h"
#include "grim_texture.h"

bool IGrim2D_cpp::grim_save_screenshot(char *path)
{
    IDirect3DSurface8 *surface = 0;
    if (grim_d3d_device->CreateImageSurface(
            grim_present_width,
            grim_present_height,
            D3DFMT_A8R8G8B8,
            &surface) < 0) {
        return false;
    }
    if (grim_d3d_device->GetFrontBuffer(surface) < 0) {
        surface->Release();
        return false;
    }
    if (D3DXSaveSurfaceToFileA(path, 0, surface, 0, 0) < 0) {
        surface->Release();
        return false;
    }
    surface->Release();
    return true;
}
