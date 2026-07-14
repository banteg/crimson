#include <windows.h>

#include "grim2d_cpp.h"
#include "grim_texture.h"

extern HINSTANCE grim_module_handle;
extern HICON grim_window_icon_handle;
extern bool grim_config_dialog_canceled;
extern IDirect3D8 *grim_d3d8_probe;
extern D3DCAPS8 grim_device_caps;
extern bool grim_config_option_54_value;
extern bool grim_config_dialog_bpp16_selected;
extern bool grim_config_dialog_windowed_selected;
extern unsigned int grim_config_selected_width;
extern unsigned int grim_config_selected_height;

BOOL CALLBACK grim_config_dialog_proc(
    HWND hwnd, UINT message, WPARAM wparam, LPARAM lparam);

bool IGrim2D_cpp::grim_apply_config(void)
{
    if (grim_window_icon_handle == 0) {
        grim_window_icon_handle =
            LoadIconA(grim_module_handle, MAKEINTRESOURCEA(0x72));
    }

    grim_config_dialog_canceled = false;
    grim_d3d8_probe = Direct3DCreate8(D3D_SDK_VERSION);
    if (grim_d3d8_probe == 0) {
        grim_error_text =
            "D3D: Could not init DirectX 8.1, (re)install it.";
        MessageBoxA(0, grim_error_text, "Grim", 0);
        return false;
    }

    grim_d3d8_probe->GetDeviceCaps(
        0, D3DDEVTYPE_HAL, &grim_device_caps);
    DialogBoxParamA(
        grim_module_handle,
        MAKEINTRESOURCEA(0x74),
        0,
        grim_config_dialog_proc,
        0);
    grim_d3d8_probe->Release();

    if (!grim_config_dialog_canceled) {
        grim_set_config_var(0x54, grim_config_option_54_value);

        if (grim_config_dialog_bpp16_selected) {
            grim_set_config_var(0x2b, (unsigned int)0x10);
        } else {
            grim_set_config_var(0x2b, (unsigned int)0x20);
        }

        grim_set_config_var(0x54, grim_config_option_54_value);
        grim_set_config_var(8, grim_config_dialog_windowed_selected);
        grim_set_config_var(0x34, false);
        grim_set_config_var(8, grim_config_dialog_windowed_selected);
        grim_set_config_var(0x29, grim_config_selected_width);
        grim_set_config_var(0x2a, grim_config_selected_height);
    }

    return !grim_config_dialog_canceled;
}
