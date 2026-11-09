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
#if CL_BUILD < 10900
extern bool grim_config_dialog_pure_software_selected;
#endif
#if CL_BUILD <= 10908
extern int grim_config_resolution_index;
#endif

BOOL CALLBACK grim_config_dialog_proc(
    HWND hwnd, UINT message, WPARAM wparam, LPARAM lparam);

bool IGrim2D_cpp::grim_apply_config(void)
{
    if (grim_window_icon_handle == 0) {
        grim_window_icon_handle =
            LoadIconA(grim_module_handle, MAKEINTRESOURCEA(0x72));
    }

    grim_config_dialog_canceled = false;
#if CL_BUILD == 10002
    IDirect3D8 *probe = Direct3DCreate8(D3D_SDK_VERSION);
    if (probe == 0)
        grim_error_text = "D3D: Could not init DirectX 8.1, (re)install it.";
    probe->GetDeviceCaps(0, D3DDEVTYPE_HAL, &grim_device_caps);
    probe->Release();
#else
    grim_d3d8_probe = Direct3DCreate8(D3D_SDK_VERSION);
    if (grim_d3d8_probe == 0) {
        grim_error_text =
            "D3D: Could not init DirectX 8.1, (re)install it.";
        MessageBoxA(0, grim_error_text, "Grim", 0);
        return false;
    }

    grim_d3d8_probe->GetDeviceCaps(
        0, D3DDEVTYPE_HAL, &grim_device_caps);
#endif
    DialogBoxParamA(
        grim_module_handle,
        MAKEINTRESOURCEA(0x74),
        0,
        grim_config_dialog_proc,
        0);
#if CL_BUILD != 10002
    grim_d3d8_probe->Release();
#endif

    if (!grim_config_dialog_canceled) {
#if CL_BUILD > 10908
        grim_set_config_var(0x54, grim_config_option_54_value);
#endif

#if CL_BUILD == 10002
        enum { bpp = 6, windowed = 3 };
#elif CL_BUILD < 10900
        enum { bpp = 9, windowed = 6, width = 7, height = 8 };
#else
        enum { bpp = 0x2b, windowed = 8, width = 0x29, height = 0x2a };
#endif
        if (grim_config_dialog_bpp16_selected) {
            grim_set_config_var(bpp, (unsigned int)0x10);
        } else {
            grim_set_config_var(bpp, (unsigned int)0x20);
        }

#if CL_BUILD < 10900
        grim_set_config_var(windowed, grim_config_dialog_windowed_selected);
        grim_set_config_var(0x34, grim_config_dialog_pure_software_selected);
#else
        grim_set_config_var(0x54, grim_config_option_54_value);
        grim_set_config_var(windowed, grim_config_dialog_windowed_selected);
        grim_set_config_var(0x34, false);
#endif
#if CL_BUILD >= 10300 && CL_BUILD <= 10908
        // The earlier configuration dialog offers four fixed resolutions instead of the adapter's modes.
        switch (grim_config_resolution_index) {
        case 0:
            grim_set_config_var(width, (unsigned int)640);
            grim_set_config_var(height, (unsigned int)480);
            break;
        case 1:
            grim_set_config_var(width, (unsigned int)800);
            grim_set_config_var(height, (unsigned int)600);
            break;
        case 2:
            grim_set_config_var(width, (unsigned int)1024);
            grim_set_config_var(height, (unsigned int)768);
            break;
        case 3:
            grim_set_config_var(width, (unsigned int)1280);
            grim_set_config_var(height, (unsigned int)1024);
            break;
        }
#elif CL_BUILD > 10908
        grim_set_config_var(windowed, grim_config_dialog_windowed_selected);
        grim_set_config_var(width, grim_config_selected_width);
        grim_set_config_var(height, grim_config_selected_height);
#endif
    }

    return !grim_config_dialog_canceled;
}
