#include "grim_texture.h"

bool grim_select_texture_format(void)
{
    if (grim_is_texture_format_supported(D3DFMT_A8R8G8B8)) {
        grim_preferred_texture_format = D3DFMT_A8R8G8B8;
        return true;
    }
    if (grim_is_texture_format_supported(D3DFMT_DXT3)) {
        grim_preferred_texture_format = D3DFMT_DXT3;
        return true;
    }
    if (grim_is_texture_format_supported(D3DFMT_A4R4G4B4)) {
        grim_preferred_texture_format = D3DFMT_A4R4G4B4;
        return true;
    }
    if (grim_is_texture_format_supported(D3DFMT_A1R5G5B5)) {
        grim_preferred_texture_format = D3DFMT_A1R5G5B5;
        return true;
    }
    if (grim_is_texture_format_supported(D3DFMT_R8G8B8)) {
        grim_preferred_texture_format = D3DFMT_R8G8B8;
        return true;
    }
    if (grim_is_texture_format_supported(D3DFMT_X8R8G8B8)) {
        grim_preferred_texture_format = D3DFMT_X8R8G8B8;
        return true;
    }
    if (grim_is_texture_format_supported(D3DFMT_R8G8B8)) {
        grim_preferred_texture_format = D3DFMT_R8G8B8;
        return true;
    }
    if (grim_is_texture_format_supported(D3DFMT_R5G6B5)) {
        grim_preferred_texture_format = D3DFMT_R5G6B5;
        return true;
    }

    grim_error_text = "D3D: No supported texture formats found.";
    return false;
}
