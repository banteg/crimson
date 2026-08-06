#include <windows.h>

#include "grim2d_cpp.h"
#include "grim_texture.h"

extern HICON grim_window_icon_handle;
extern IDirect3D8 *grim_d3d8_probe;
extern UINT grim_selected_adapter_index;
extern D3DFORMAT grim_texture_format;
extern D3DFORMAT grim_preferred_texture_format;
extern grim_config_value_t grim_config_values[128];
extern bool grim_config_option_54_value;
extern D3DFORMAT grim_advanced_texture_formats[6];
extern int grim_advanced_texture_format_count;

BOOL CALLBACK grim_advanced_config_dialog_proc(
    HWND hwnd, UINT message, WPARAM wparam, LPARAM lparam)
{
    switch (message) {
    case WM_CLOSE:
        EndDialog(hwnd, LOWORD(wparam));
        break;

    case WM_INITDIALOG: {
        SendMessageA(hwnd, WM_SETICON, 1, (LPARAM)grim_window_icon_handle);
        SendMessageA(hwnd, WM_SETICON, 0, (LPARAM)grim_window_icon_handle);

        grim_advanced_texture_formats[0] = D3DFMT_UNKNOWN;
        grim_advanced_texture_format_count = 1;
        SendMessageA(
            GetDlgItem(hwnd, 0x402),
            CB_ADDSTRING,
            0,
            (LPARAM)"Autodetect (select the best available)");

        if (grim_d3d8_probe->CheckDeviceFormat(
                grim_selected_adapter_index,
                D3DDEVTYPE_HAL,
                grim_texture_format,
                0,
                D3DRTYPE_TEXTURE,
                D3DFMT_A8R8G8B8) >= 0) {
            grim_advanced_texture_formats[grim_advanced_texture_format_count] =
                D3DFMT_A8R8G8B8;
            ++grim_advanced_texture_format_count;
            SendMessageA(
                GetDlgItem(hwnd, 0x402),
                CB_ADDSTRING,
                0,
                (LPARAM)"32-bit A8R8G8B8 (highest detail)");
        }
        if (grim_d3d8_probe->CheckDeviceFormat(
                grim_selected_adapter_index,
                D3DDEVTYPE_HAL,
                grim_texture_format,
                0,
                D3DRTYPE_TEXTURE,
                D3DFMT_A8R3G3B2) >= 0) {
            grim_advanced_texture_formats[grim_advanced_texture_format_count] =
                D3DFMT_A8R3G3B2;
            ++grim_advanced_texture_format_count;
            SendMessageA(
                GetDlgItem(hwnd, 0x402),
                CB_ADDSTRING,
                0,
                (LPARAM)"16-bit A8R3G3B2");
        }
        if (grim_d3d8_probe->CheckDeviceFormat(
                grim_selected_adapter_index,
                D3DDEVTYPE_HAL,
                grim_texture_format,
                0,
                D3DRTYPE_TEXTURE,
                D3DFMT_A4R4G4B4) >= 0) {
            grim_advanced_texture_formats[grim_advanced_texture_format_count] =
                D3DFMT_A4R4G4B4;
            ++grim_advanced_texture_format_count;
            SendMessageA(
                GetDlgItem(hwnd, 0x402),
                CB_ADDSTRING,
                0,
                (LPARAM)"16-bit A4R4G4B4");
        }
        if (grim_d3d8_probe->CheckDeviceFormat(
                grim_selected_adapter_index,
                D3DDEVTYPE_HAL,
                grim_texture_format,
                0,
                D3DRTYPE_TEXTURE,
                D3DFMT_DXT3) >= 0) {
            grim_advanced_texture_formats[grim_advanced_texture_format_count] =
                D3DFMT_DXT3;
            ++grim_advanced_texture_format_count;
            SendMessageA(
                GetDlgItem(hwnd, 0x402),
                CB_ADDSTRING,
                0,
                (LPARAM)"DXT3 compressed");
        }
        if (grim_d3d8_probe->CheckDeviceFormat(
                grim_selected_adapter_index,
                D3DDEVTYPE_HAL,
                grim_texture_format,
                0,
                D3DRTYPE_TEXTURE,
                D3DFMT_DXT5) >= 0) {
            grim_advanced_texture_formats[grim_advanced_texture_format_count] =
                D3DFMT_DXT5;
            ++grim_advanced_texture_format_count;
            SendMessageA(
                GetDlgItem(hwnd, 0x402),
                CB_ADDSTRING,
                0,
                (LPARAM)"DXT5 compressed");
        }
        SendMessageA(GetDlgItem(hwnd, 0x402), CB_SETCURSEL, 0, 0);

        SendMessageA(
            GetDlgItem(hwnd, 0x408),
            CB_ADDSTRING,
            0,
            (LPARAM)"Double (slowest, 4x more mem used)");
        SendMessageA(
            GetDlgItem(hwnd, 0x408),
            CB_ADDSTRING,
            0,
            (LPARAM)"Full (default)");
        SendMessageA(
            GetDlgItem(hwnd, 0x408),
            CB_ADDSTRING,
            0,
            (LPARAM)"Half (faster, 4x less memory used)");
        SendMessageA(
            GetDlgItem(hwnd, 0x408),
            CB_ADDSTRING,
            0,
            (LPARAM)"None (static texture, no decals stored)");
        SendMessageA(GetDlgItem(hwnd, 0x408), CB_SETCURSEL, 1, 0);

        if (*(float *)grim_config_values[0x59].words == 0.5f) {
            SendMessageA(GetDlgItem(hwnd, 0x408), CB_SETCURSEL, 0, 0);
        } else if (*(float *)grim_config_values[0x59].words == 1.0f) {
            SendMessageA(GetDlgItem(hwnd, 0x408), CB_SETCURSEL, 1, 0);
        } else if (*(float *)grim_config_values[0x59].words == 2.0f) {
            SendMessageA(GetDlgItem(hwnd, 0x408), CB_SETCURSEL, 2, 0);
        } else if (*(float *)grim_config_values[0x59].words == 4.0f) {
            SendMessageA(GetDlgItem(hwnd, 0x408), CB_SETCURSEL, 3, 0);
        } else {
            *(float *)grim_config_values[0x59].words = 1.0f;
            SendMessageA(GetDlgItem(hwnd, 0x408), CB_SETCURSEL, 1, 0);
        }

        grim_config_option_54_value = grim_config_values[0x54];
        if (grim_config_option_54_value) {
            SendMessageA(GetDlgItem(hwnd, 0x408), CB_SETCURSEL, 3, 0);
        }

        if (*(unsigned char *)grim_config_values[0x53].words == 1) {
            SendMessageA(GetDlgItem(hwnd, 0x405), BM_SETCHECK, 1, 0);
        } else {
            SendMessageA(GetDlgItem(hwnd, 0x405), BM_SETCHECK, 0, 0);
        }
        if (*(unsigned char *)grim_config_values[0x58].words) {
            SendMessageA(GetDlgItem(hwnd, 0x404), BM_SETCHECK, 1, 0);
        } else {
            SendMessageA(GetDlgItem(hwnd, 0x404), BM_SETCHECK, 0, 0);
        }
        return TRUE;
    }

    case WM_COMMAND:
        switch (LOWORD(wparam)) {
        case 0x3e9:
            EndDialog(hwnd, 0x3e9);
            return FALSE;

        case 0x403:
            *(bool *)grim_config_values[0x58].words =
                SendMessageA(
                    GetDlgItem(hwnd, 0x404), BM_GETCHECK, 0, 0) != 0;
            grim_preferred_texture_format =
                grim_advanced_texture_formats[SendMessageA(
                    GetDlgItem(hwnd, 0x402), CB_GETCURSEL, 0, 0)];
            *(bool *)grim_config_values[0x53].words =
                SendMessageA(
                    GetDlgItem(hwnd, 0x405), BM_GETCHECK, 0, 0) != 0;
            grim_config_option_54_value = false;

            switch (SendMessageA(
                GetDlgItem(hwnd, 0x408), CB_GETCURSEL, 0, 0)) {
            case 0:
                *(float *)grim_config_values[0x59].words = 0.5f;
                EndDialog(hwnd, 0x403);
                return FALSE;
            case 1:
                *(float *)grim_config_values[0x59].words = 1.0f;
                EndDialog(hwnd, 0x403);
                return FALSE;
            case 2:
                *(float *)grim_config_values[0x59].words = 2.0f;
                EndDialog(hwnd, 0x403);
                return FALSE;
            case 3:
                grim_config_option_54_value = true;
                EndDialog(hwnd, 0x403);
                return FALSE;
            default:
                *(float *)grim_config_values[0x59].words = 1.0f;
                EndDialog(hwnd, 0x403);
                return FALSE;
            }

        case 0x406:
            *(bool *)grim_config_values[0x53].words = false;
            SendMessageA(GetDlgItem(hwnd, 0x405), BM_SETCHECK, 0, 0);
            *(bool *)grim_config_values[0x58].words = true;
            SendMessageA(GetDlgItem(hwnd, 0x404), BM_SETCHECK, 1, 0);
            *(float *)grim_config_values[0x59].words = 1.0f;
            SendMessageA(GetDlgItem(hwnd, 0x408), CB_SETCURSEL, 1, 0);
            SendMessageA(GetDlgItem(hwnd, 0x402), CB_SETCURSEL, 0, 0);
            return FALSE;
        }
        break;
    }

    return FALSE;
}
