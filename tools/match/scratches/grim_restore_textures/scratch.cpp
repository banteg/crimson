#include "grim2d_cpp.h"
#include "grim_texture.h"

extern unsigned char grim_dc_mode_active;
extern unsigned char grim_texture_backup_pending;
extern grim_config_value_t grim_config_values[128];

extern "C" void grim_noop(char *message, ...);

bool grim_restore_textures(void)
{
    if (grim_dc_mode_active) {
        return false;
    }

    grim_noop("RestoreDynamics\n", 0);
    if (!grim_texture_backup_pending) {
        grim_noop("(not backedup) \n", 0);
        if (!grim_texture_backup_pending) {
            return false;
        }
    }

    IDirect3DSurface8 *surface = 0;
    for (int i = 0; i <= grim_texture_slot_max_index; ++i) {
        if (grim_texture_slots[i] != 0 &&
            grim_texture_slots[i]->owns_texture &&
            grim_texture_slots[i]->backup != 0) {
            grim_noop(grim_texture_slots[i]->name, i);

            if (grim_texture_slots[i]->texture != 0 &&
                grim_texture_slots[i]->texture->GetSurfaceLevel(
                    0, &surface) < 0) {
                grim_error_text =
                    "D3D: Unable to recreate texture. (GetSurfaceLevel)";
                grim_noop(grim_error_text, i);
                return false;
            }

            if (grim_d3d_device->CopyRects(
                    grim_texture_slots[i]->backup, 0, 0, surface, 0) < 0) {
                if (surface != 0 && surface->Release() <= 0) {
                    surface = 0;
                }
                if (grim_texture_slots[i]->backup != 0 &&
                    grim_texture_slots[i]->backup->Release() <= 0) {
                    grim_texture_slots[i]->backup = 0;
                }

                grim_texture_backup_pending = 0;
                grim_error_text =
                    "D3D: Unable to restore texture. (CopyRects)";
                grim_config_values[0x57] = true;
                grim_noop(grim_error_text, i);
                return false;
            }

            if (surface != 0 && surface->Release() <= 0) {
                surface = 0;
            }
            if (grim_texture_slots[i]->backup != 0 &&
                grim_texture_slots[i]->backup->Release() <= 0) {
                grim_texture_slots[i]->backup = 0;
            }
        }
    }

    grim_texture_backup_pending = 0;
    return true;
}
