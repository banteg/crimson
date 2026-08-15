#include "grim2d_cpp.h"
#include "grim_texture.h"

extern unsigned char grim_texture_backup_pending;
extern grim_config_value_t grim_config_values[128];

extern "C" void grim_noop(char *message, int value);

bool grim_backup_textures(void)
{
    grim_noop("Backup Dynamics\n", 0);
    if (grim_texture_backup_pending) {
        grim_noop("(already backed up)\n", 0);
        if (grim_texture_backup_pending) {
            return true;
        }
    }

    IDirect3DSurface8 *surface = 0;
    for (int i = 0; i <= grim_texture_slot_max_index; ++i) {
        if (grim_texture_slots[i] != 0 &&
            grim_texture_slots[i]->owns_texture) {
            grim_noop(grim_texture_slots[i]->name, i);

            if (grim_d3d_device->CreateImageSurface(
                    grim_texture_slots[i]->width,
                    grim_texture_slots[i]->height,
                    grim_texture_format,
                    &grim_texture_slots[i]->backup) < 0) {
                grim_error_text =
                    "D3D: Unable to backup texture. (CreateImageSurface)";
                grim_noop(grim_error_text, 0);
                grim_noop(grim_error_text, 0);
                return false;
            }

            if (grim_texture_slots[i]->texture->GetSurfaceLevel(
                    0, &surface) < 0) {
                if (grim_texture_slots[i]->backup != 0 &&
                    grim_texture_slots[i]->backup->Release() <= 0) {
                    grim_texture_slots[i]->backup = 0;
                }
                grim_error_text =
                    "D3D: Unable to backup texture. (GetSurfaceLevel)";
                grim_noop(grim_error_text, 0);
                grim_noop(grim_error_text, i);
                return false;
            }

            HRESULT result = grim_d3d_device->CopyRects(
                surface, 0, 0, grim_texture_slots[i]->backup, 0);
            if (result < 0) {
                if (grim_texture_slots[i]->backup != 0 &&
                    grim_texture_slots[i]->backup->Release() <= 0) {
                    grim_texture_slots[i]->backup = 0;
                }
                if (surface != 0 && surface->Release() <= 0) {
                    surface = 0;
                }

                grim_error_text =
                    "D3D: Unable to backup texture. (CopyRects)";
                grim_noop(grim_error_text, i);
                grim_config_values[0x57] = true;

                if (result == D3DERR_DEVICELOST) {
                    grim_noop("D3DERR_DEVICELOST", result);
                    return false;
                }
                if (result == D3DERR_INVALIDCALL) {
                    grim_noop("D3DERR_INVALIDCALL", result);
                    return false;
                }
                grim_noop("<- hResult", result);
                return false;
            }

            if (surface != 0 && surface->Release() <= 0) {
                surface = 0;
            }
        }
    }

    grim_texture_backup_pending = 1;
    return true;
}
