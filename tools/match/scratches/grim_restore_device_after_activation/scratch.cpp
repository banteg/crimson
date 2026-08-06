#include "grim2d_cpp.h"
#include "grim_texture.h"

extern unsigned char grim_device_ready;
extern int grim_device_reset_retry_count;
extern HWND grim_main_window_hwnd;
extern grim_config_value_t grim_config_values[128];

extern "C" void grim_noop(char *message, int value);
extern "C" void grim_noop_value(int value);
void grim_apply_render_state(void);
bool grim_restore_textures(void);

bool grim_restore_device_after_activation(void)
{
    HRESULT status;
    int i;
    int j;
    int k;
    int l;

    if (grim_d3d_device != 0) {
        status = grim_d3d_device->TestCooperativeLevel();
        grim_device_ready = status == D3D_OK;
        if (grim_device_ready || status != D3DERR_DEVICENOTRESET) {
            goto succeeded;
        }

        Sleep(100);
        if (grim_render_target_surface != 0 &&
            grim_render_target_surface->Release() <= 0) {
            grim_render_target_surface = 0;
        }
        if (grim_backbuffer_surface != 0 &&
            grim_backbuffer_surface->Release() <= 0) {
            grim_backbuffer_surface = 0;
        }

        for (i = 0; i <= grim_texture_slot_max_index; ++i) {
            if (grim_texture_slots[i] != 0 &&
                grim_texture_slots[i]->owns_texture &&
                grim_texture_slots[i]->texture != 0 &&
                grim_texture_slots[i]->texture->Release() <= 0) {
                grim_texture_slots[i]->texture = 0;
            }
        }

        if (grim_d3d_device->Reset(
                (D3DPRESENT_PARAMETERS *)&grim_present_width) == D3D_OK) {
            grim_apply_render_state();
            for (j = 0; j <= grim_texture_slot_max_index; ++j) {
                if (grim_texture_slots[j] != 0 &&
                    grim_texture_slots[j]->owns_texture &&
                    grim_d3d_device->CreateTexture(
                        grim_texture_slots[j]->width,
                        grim_texture_slots[j]->height, 1, D3DUSAGE_RENDERTARGET,
                        grim_texture_format, D3DPOOL_DEFAULT,
                        &grim_texture_slots[j]->texture) < 0) {
                    grim_error_text = "D3D: Unable to recreate a texture.";
                    grim_texture_slots[j]->texture = 0;
                    grim_noop(grim_error_text, 0);
                    grim_noop_value(j);
                }
            }

            grim_restore_textures();
            grim_device_reset_retry_count = 0;
            return true;
        }

        ++grim_device_reset_retry_count;
        Sleep(500);

        if (grim_device_reset_retry_count == 5) {
            for (k = 0; k <= grim_texture_slot_max_index; ++k) {
                if (grim_texture_slots[k] != 0 &&
                    grim_texture_slots[k]->owns_texture) {
                    if (grim_texture_slots[k]->backup != 0 &&
                        grim_texture_slots[k]->backup->Release() <= 0) {
                        grim_texture_slots[k]->backup = 0;
                    }
                    if (grim_texture_slots[k]->texture != 0 &&
                        grim_texture_slots[k]->texture->Release() <= 0) {
                        grim_texture_slots[k]->texture = 0;
                    }
                    grim_config_values[0x57] = true;
                }
            }
        }

        if (grim_device_reset_retry_count <= 6) {
            goto succeeded;
        }

        grim_error_text = "D3D: Unable to restore device.";
        if (MessageBoxA(grim_main_window_hwnd, grim_error_text, "Grim",
                        MB_RETRYCANCEL) != IDCANCEL) {
            for (l = 0; l <= grim_texture_slot_max_index; ++l) {
                if (grim_texture_slots[l] != 0 &&
                    grim_texture_slots[l]->owns_texture) {
                    if (grim_texture_slots[l]->backup != 0 &&
                        grim_texture_slots[l]->backup->Release() <= 0) {
                        grim_texture_slots[l]->backup = 0;
                    }
                    if (grim_texture_slots[l]->texture != 0 &&
                        grim_texture_slots[l]->texture->Release() <= 0) {
                        grim_texture_slots[l]->texture = 0;
                    }
                    grim_config_values[0x57] = true;
                }
            }
            goto succeeded;
        }
    }
    goto failed;

succeeded:
    return true;
failed:
    return false;
}
