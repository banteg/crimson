#include <windows.h>

#include "grim2d_cpp.h"
#include "grim_texture.h"

extern HWND grim_config_dialog_hwnd;
extern IDirect3D8 *grim_d3d8_probe;
extern D3DCAPS8 grim_device_caps;
extern grim_config_value_t grim_config_values[128];
extern unsigned char grim_caps_can_render_windowed;
extern unsigned char grim_caps_x8r8g8b8_supported;
extern bool grim_config_option_54_value;

int grim_config_dialog_populate_display_modes(void)
{
    grim_caps_can_render_windowed =
        (grim_device_caps.Caps2 >> 19) & 1;
    SendMessageA(
        GetDlgItem(grim_config_dialog_hwnd, 0x3ed),
        BM_SETCHECK,
        grim_config_values[0x34].words[0] & 0xff,
        0);

    grim_config_option_54_value = grim_config_values[0x54];
    grim_caps_x8r8g8b8_supported =
        grim_d3d8_probe->CheckDeviceType(
            0,
            D3DDEVTYPE_HAL,
            D3DFMT_X8R8G8B8,
            D3DFMT_X8R8G8B8,
            FALSE) >= 0;

    SendMessageA(
        GetDlgItem(grim_config_dialog_hwnd, 0x3f9),
        CB_RESETCONTENT,
        0,
        0);

    if (grim_caps_can_render_windowed) {
        SendMessageA(
            GetDlgItem(grim_config_dialog_hwnd, 0x3f9),
            CB_ADDSTRING,
            0,
            (LPARAM)"640x480 (windowed)");
        SendMessageA(
            GetDlgItem(grim_config_dialog_hwnd, 0x3f9),
            CB_ADDSTRING,
            0,
            (LPARAM)"800x600 (windowed)");
        SendMessageA(
            GetDlgItem(grim_config_dialog_hwnd, 0x3f9),
            CB_ADDSTRING,
            0,
            (LPARAM)"960x600 (wide window)");
        SendMessageA(
            GetDlgItem(grim_config_dialog_hwnd, 0x3f9),
            CB_ADDSTRING,
            0,
            (LPARAM)"1024x768 (windowed)");
    }

    SendMessageA(
        GetDlgItem(grim_config_dialog_hwnd, 0x3f9),
        CB_ADDSTRING,
        0,
        (LPARAM)"640x480x16");
    SendMessageA(
        GetDlgItem(grim_config_dialog_hwnd, 0x3f9),
        CB_ADDSTRING,
        0,
        (LPARAM)"800x600x16");
    SendMessageA(
        GetDlgItem(grim_config_dialog_hwnd, 0x3f9),
        CB_ADDSTRING,
        0,
        (LPARAM)"960x600x16 (wide)");
    SendMessageA(
        GetDlgItem(grim_config_dialog_hwnd, 0x3f9),
        CB_ADDSTRING,
        0,
        (LPARAM)"1024x768x16");

    if (grim_caps_x8r8g8b8_supported) {
        SendMessageA(
            GetDlgItem(grim_config_dialog_hwnd, 0x3f9),
            CB_ADDSTRING,
            0,
            (LPARAM)"640x480x32");
        SendMessageA(
            GetDlgItem(grim_config_dialog_hwnd, 0x3f9),
            CB_ADDSTRING,
            0,
            (LPARAM)"800x600x32");
        SendMessageA(
            GetDlgItem(grim_config_dialog_hwnd, 0x3f9),
            CB_ADDSTRING,
            0,
            (LPARAM)"960x600x32 (wide)");
        SendMessageA(
            GetDlgItem(grim_config_dialog_hwnd, 0x3f9),
            CB_ADDSTRING,
            0,
            (LPARAM)"1024x768x32");
    }

    int selection;
    unsigned int width = grim_config_values[0x29].words[0];
    if (width == 640) {
        selection = 0;
    } else if (width == 800) {
        selection = 1;
    } else if (width == 960) {
        selection = 2;
    } else if (width == 1024) {
        selection = 3;
    } else if (width == 1680) {
        selection = 4;
    } else {
        selection = 1;
    }

    if (*(unsigned char *)grim_config_values[8].words != 1 ||
        !grim_caps_can_render_windowed) {
        unsigned int bpp = grim_config_values[0x2b].words[0];
        if (bpp == 16) {
            selection += 4;
        } else if (bpp == 32) {
            selection += 8;
        }
        if (!grim_caps_can_render_windowed) {
            selection -= 4;
        }
    }

    return SendMessageA(
        GetDlgItem(grim_config_dialog_hwnd, 0x3f9),
        CB_SETCURSEL,
        selection,
        0);
}
