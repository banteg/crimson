#include "grim2d_cpp.h"
#include "grim_texture.h"

extern int grim_device_reset_retry_count;
extern HWND grim_main_window_hwnd;
extern grim_config_value_t grim_config_values[128];

extern "C" void grim_noop(char *message, int value);
void grim_apply_render_state(void);
bool grim_restore_textures(void);

HRESULT grim_try_reset_device(void)
{
    grim_noop("Entering D3D_TryResetDevice..\n", 0);

    if (grim_render_target_surface != 0 &&
        grim_render_target_surface->Release() <= 0) {
        grim_render_target_surface = 0;
    }
    if (grim_backbuffer_surface != 0 &&
        grim_backbuffer_surface->Release() <= 0) {
        grim_backbuffer_surface = 0;
    }

    for (int i = 0; i <= grim_texture_slot_max_index; ++i) {
        if (grim_texture_slots[i] != 0 &&
            grim_texture_slots[i]->owns_texture &&
            grim_texture_slots[i]->texture != 0 &&
            grim_texture_slots[i]->texture->Release() <= 0) {
            grim_texture_slots[i]->texture = 0;
        }
    }

    int j;
    int k;
    bool canceled = false;
    if (grim_d3d_device->Reset(
            (D3DPRESENT_PARAMETERS *)&grim_present_width) != D3D_OK) {
        do {
            ++grim_device_reset_retry_count;
            Sleep(500);

            if (grim_device_reset_retry_count >= 4) {
                grim_error_text = "D3D: Unable to restore device.";
                if (MessageBoxA(
                        grim_main_window_hwnd,
                        grim_error_text,
                        "Grim",
                        MB_RETRYCANCEL) == IDCANCEL) {
                    canceled = true;
                    break;
                }

                for (j = 0; j <= grim_texture_slot_max_index; ++j) {
                    if (grim_texture_slots[j] != 0 &&
                        grim_texture_slots[j]->owns_texture) {
                        if (grim_texture_slots[j]->backup != 0 &&
                            grim_texture_slots[j]->backup->Release() <= 0) {
                            grim_texture_slots[j]->backup = 0;
                        }
                        if (grim_texture_slots[j]->texture != 0 &&
                            grim_texture_slots[j]->texture->Release() <= 0) {
                            grim_texture_slots[j]->texture = 0;
                        }
                        grim_config_values[0x57] = true;
                    }
                }
            }
        } while (grim_d3d_device->Reset(
                     (D3DPRESENT_PARAMETERS *)&grim_present_width) !=
                 D3D_OK);
    }

    if (!canceled) {
        grim_apply_render_state();
        for (k = 0; k <= grim_texture_slot_max_index; ++k) {
            if (grim_texture_slots[k] != 0 &&
                grim_texture_slots[k]->owns_texture) {
                if (grim_d3d_device->CreateTexture(
                        grim_texture_slots[k]->width,
                        grim_texture_slots[k]->height,
                        1,
                        D3DUSAGE_RENDERTARGET,
                        grim_texture_format,
                        D3DPOOL_DEFAULT,
                        &grim_texture_slots[k]->texture) < 0) {
                    grim_error_text = "D3D: Unable to recreate a texture.";
                    grim_noop(grim_error_text, 0);
                    grim_texture_slots[k]->texture = 0;
                    Sleep(200);
                }
            }
        }

        if (!grim_restore_textures()) {
            grim_noop("RestoreDynamics() == false) at line 1006", 0);
        }
        grim_noop(
            "Done D3D_TryResetDevice ok..\n",
            grim_device_reset_retry_count);
        grim_device_reset_retry_count = 0;
        return D3D_OK;
    }

    grim_noop(
        "Done D3D_TryResetDevice, failed to reset device..\n", 0);
    return D3DERR_DEVICENOTRESET;
}
