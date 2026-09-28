#include <windows.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "grim_texture.h"

extern "C" HRESULT WINAPI HlinkNavigateString(
    IUnknown *unknown,
    LPCWSTR target);

extern HINSTANCE grim_module_handle;
extern HICON grim_window_icon_handle;
extern HWND grim_config_dialog_hwnd;
extern SYSTEMTIME grim_config_dialog_system_time;
extern IDirect3D8 *grim_d3d8_probe;
extern D3DADAPTER_IDENTIFIER8 grim_adapter_identifier;
extern char grim_adapter_description[512];
extern bool grim_config_dialog_has_supported_adapter;
extern bool grim_config_dialog_option_3ef_checked;
extern bool grim_config_dialog_windowed_selected;
extern bool grim_config_dialog_bpp16_selected;
extern bool grim_config_dialog_canceled;
extern UINT grim_selected_adapter_index;
extern unsigned int grim_config_selected_width;
extern unsigned int grim_config_selected_height;
extern unsigned int grim_config_mode_width;
extern unsigned int grim_config_mode_height;
extern unsigned int grim_config_mode_bpp;

bool grim_config_blob_load(void);
int grim_config_dialog_populate_display_modes(void);
BOOL CALLBACK grim_parental_lock_dialog_proc(
    HWND hwnd, UINT message, WPARAM wparam, LPARAM lparam);
BOOL CALLBACK grim_advanced_config_dialog_proc(
    HWND hwnd, UINT message, WPARAM wparam, LPARAM lparam);

BOOL CALLBACK grim_config_dialog_proc(
    HWND hwnd, UINT message, WPARAM wparam, LPARAM lparam)
{
    char adapter_label[512];

    switch (message) {
    case WM_CLOSE:
        grim_config_dialog_canceled = true;
        EndDialog(hwnd, LOWORD(wparam));
        break;

    case WM_INITDIALOG: {
        grim_config_dialog_hwnd = hwnd;
        ShowWindow(GetDlgItem(hwnd, 0x3f2), SW_SHOW);
        ShowWindow(GetDlgItem(hwnd, 0x40b), SW_HIDE);
        SendMessageA(hwnd, WM_SETICON, 1, (LPARAM)grim_window_icon_handle);
        SendMessageA(hwnd, WM_SETICON, 0, (LPARAM)grim_window_icon_handle);
        GetLocalTime(&grim_config_dialog_system_time);

        int adapter_count = grim_d3d8_probe->GetAdapterCount();
        grim_config_dialog_has_supported_adapter = false;
        for (int adapter = 0; adapter < adapter_count; ++adapter) {
            grim_d3d8_probe->GetAdapterIdentifier(
                adapter,
                D3DENUM_NO_WHQL_LEVEL,
                &grim_adapter_identifier);
            if (adapter == 0) {
                sprintf(
                    adapter_label,
                    "%s (default)",
                    grim_adapter_description);
            } else {
                sprintf(adapter_label, "%s", grim_adapter_description);
            }

            if (grim_d3d8_probe->CheckDeviceType(
                    adapter,
                    D3DDEVTYPE_HAL,
                    D3DFMT_R5G6B5,
                    D3DFMT_R5G6B5,
                    FALSE) >= 0 ||
                grim_d3d8_probe->CheckDeviceType(
                    adapter,
                    D3DDEVTYPE_HAL,
                    D3DFMT_X8R8G8B8,
                    D3DFMT_X8R8G8B8,
                    FALSE) >= 0) {
                SendMessageA(
                    GetDlgItem(hwnd, 0x3f1),
                    CB_ADDSTRING,
                    0,
                    (LPARAM)adapter_label);
                grim_config_dialog_has_supported_adapter = true;
            }
        }

        SendMessageA(
            GetDlgItem(hwnd, 0x3f1),
            CB_SETCURSEL,
            grim_selected_adapter_index,
            0);
        grim_selected_adapter_index = SendMessageA(
            GetDlgItem(hwnd, 0x3f1), CB_GETCURSEL, 0, 0);
        grim_config_dialog_populate_display_modes();

        if (!grim_config_dialog_has_supported_adapter) {
            SendMessageA(
                GetDlgItem(hwnd, 0x3f1),
                CB_ADDSTRING,
                0,
                (LPARAM)"No supported display adapters detected");
            if (MessageBoxA(
                    hwnd,
                    "No supported display adapters were found on your system.\n"
                    "You might not have Direct3D 8.1 compatible display adapter installed.\n\n"
                    "Would you still like to try and run Crimsonland?",
                    "Crimsonland",
                    0x33) != IDYES) {
                grim_config_dialog_canceled = true;
                EndDialog(hwnd, LOWORD(wparam));
            }
        }
        return TRUE;
    }

    case WM_COMMAND: {
        unsigned int command = LOWORD(wparam);
        switch (command) {
        case 0x3f1:
            grim_selected_adapter_index = SendMessageA(
                GetDlgItem(hwnd, 0x3f1), CB_GETCURSEL, 0, 0);
            grim_config_dialog_populate_display_modes();
            return FALSE;

        case 0x3fb:
            if (!grim_config_blob_load()) {
                MessageBoxA(
                    hwnd,
                    "Unable to load configuration file.\n"
                    "You can't set parental lock.",
                    "Parental lock problem",
                    MB_ICONASTERISK);
                return FALSE;
            }
            DialogBoxParamA(
                grim_module_handle,
                MAKEINTRESOURCEA(0x89),
                hwnd,
                grim_parental_lock_dialog_proc,
                0);
            return FALSE;

        case 0x3fc:
            grim_selected_adapter_index = SendMessageA(
                GetDlgItem(hwnd, 0x3f1), CB_GETCURSEL, 0, 0);
            DialogBoxParamA(
                grim_module_handle,
                MAKEINTRESOURCEA(0x8a),
                hwnd,
                grim_advanced_config_dialog_proc,
                0);
            return FALSE;

        case 0x3f2:
            if (HlinkNavigateString(
                    0, L"http://www.crimsonland.com") < 0) {
                MessageBoxA(
                    0,
                    "Failed to open browser at http://www.crimsonland.com/",
                    "Crimsonland",
                    MB_ICONEXCLAMATION);
            }
            return FALSE;

        case 0x3f5:
            if (WinExec("explorer.exe manual.html", 3) <= 31) {
                MessageBoxA(
                    0,
                    "Failed to open the Crimsonland Manual html file.",
                    "Crimsonland",
                    MB_ICONEXCLAMATION);
            }
            return FALSE;

        case 0x3e8: {
            grim_config_dialog_option_3ef_checked = SendMessageA(
                GetDlgItem(hwnd, 0x3ef), BM_GETCHECK, 0, 0) != 0;
            LRESULT selection = SendMessageA(
                GetDlgItem(hwnd, 0x3f9), CB_GETCURSEL, 0, 0);
            char selected_mode[512] = {0};
            SendMessageA(
                GetDlgItem(hwnd, 0x3f9),
                CB_GETLBTEXT,
                selection,
                (LPARAM)selected_mode);

            grim_config_dialog_windowed_selected =
                strstr(selected_mode, "window") != 0;
            char *height = strchr(selected_mode, 'x');
            *height = 0;
            ++height;
            char *bpp = strchr(height, 'x');
            if (bpp == 0) {
                bpp = "32";
            } else {
                *bpp = 0;
                ++bpp;
                bpp[3] = 0;
            }

            grim_config_selected_width = atoi(selected_mode);
            grim_config_selected_height = atoi(height);
            grim_config_mode_height = grim_config_selected_height;
            grim_config_mode_width = grim_config_selected_width;
            grim_config_dialog_bpp16_selected = atoi(bpp) == 16;
            grim_config_mode_bpp =
                grim_config_dialog_bpp16_selected ? 16 : 32;
            sprintf(
                selected_mode,
                "w: %d h %d bpp %d\n",
                grim_config_selected_width,
                grim_config_selected_height,
                (*(unsigned int *)&grim_config_dialog_bpp16_selected) &
                    0xff);
            grim_config_dialog_canceled = false;
            grim_selected_adapter_index = SendMessageA(
                GetDlgItem(hwnd, 0x3f1), CB_GETCURSEL, 0, 0);
            EndDialog(hwnd, command);
            break;
        }

        case 0x3e9:
            grim_config_dialog_canceled = true;
            EndDialog(hwnd, command);
            break;
        }
        break;
    }
    }

    return FALSE;
}
