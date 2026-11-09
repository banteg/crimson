#include <windows.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cl_build.h"
#include "grim_texture.h"
#if CL_BUILD < 10900
#include "grim2d_cpp.h"
#endif

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
#if CL_BUILD < 10900
extern D3DCAPS8 grim_device_caps;
extern bool grim_config_dialog_pure_software_selected;
extern grim_config_value_t grim_config_values[128];
#endif
#if CL_BUILD == 10400 || CL_BUILD == 10908
extern unsigned char grim_caps_can_render_windowed;
#endif
#if CL_BUILD == 10908
extern bool grim_windowed_mode_enabled;
#endif
#if CL_BUILD >= 10300 && CL_BUILD <= 10908
extern int grim_config_resolution_index;
#endif

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
#if CL_BUILD >= 10900
        grim_config_dialog_hwnd = hwnd;
        ShowWindow(GetDlgItem(hwnd, 0x3f2), SW_SHOW);
        ShowWindow(GetDlgItem(hwnd, 0x40b), SW_HIDE);
#endif
        SendMessageA(hwnd, WM_SETICON, 1, (LPARAM)grim_window_icon_handle);
        SendMessageA(hwnd, WM_SETICON, 0, (LPARAM)grim_window_icon_handle);
#if CL_BUILD >= 10400
        GetLocalTime(&grim_config_dialog_system_time);
#endif
#if CL_BUILD < 10900
        if (!(grim_device_caps.Caps2 & D3DCAPS2_CANRENDERWINDOWED)) {
#if CL_BUILD == 10400
            grim_caps_can_render_windowed = false;
#endif
            EnableWindow(GetDlgItem(hwnd, 0x3ec), FALSE);
        }
#if CL_BUILD >= 10300
        else {
#if CL_BUILD == 10400
            grim_caps_can_render_windowed = true;
#endif
            SendMessageA(GetDlgItem(hwnd, 0x3ec), BM_SETCHECK,
                grim_config_values[6].words[CL_BUILD < 10400 ? 2 : 0] & 0xff, 0);
            if (grim_config_values[6]) {
                EnableWindow(GetDlgItem(hwnd, 0x3ea), FALSE);
                EnableWindow(GetDlgItem(hwnd, 0x3eb), FALSE);
            }
        }
        SendMessageA(GetDlgItem(hwnd, 0x3ed), BM_SETCHECK,
            grim_config_values[52].words[CL_BUILD < 10400 ? 2 : 0] & 0xff, 0);
#endif
#endif

#if CL_BUILD >= 10300
        int adapter_count = grim_d3d8_probe->GetAdapterCount();
#if CL_BUILD >= 10900
        grim_config_dialog_has_supported_adapter = false;
#endif
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

#if CL_BUILD < 10900
            SendMessageA(GetDlgItem(hwnd, 0x3f1), LB_ADDSTRING, 0, (LPARAM)adapter_label);
#else
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
#endif
        }

#if CL_BUILD < 10900
        SendMessageA(GetDlgItem(hwnd, 0x3f0), LB_ADDSTRING, 0, (LPARAM)"640x480");
        SendMessageA(GetDlgItem(hwnd, 0x3f0), LB_ADDSTRING, 0, (LPARAM)"800x600");
        SendMessageA(GetDlgItem(hwnd, 0x3f0), LB_ADDSTRING, 0, (LPARAM)"1024x768");
        unsigned int width = grim_config_values[7].words[0];
        if (width == 640) {
            SendMessageA(GetDlgItem(hwnd, 0x3f0), LB_SETCURSEL, 0, 0);
        } else if (width == 800) {
            SendMessageA(GetDlgItem(hwnd, 0x3f0), LB_SETCURSEL, 1, 0);
        } else if (width == 1024) {
            SendMessageA(GetDlgItem(hwnd, 0x3f0), LB_SETCURSEL, 2, 0);
        } else if (width == 1280) {
            SendMessageA(GetDlgItem(hwnd, 0x3f0), LB_ADDSTRING, 0, (LPARAM)"1280x1024");
            SendMessageA(GetDlgItem(hwnd, 0x3f0), LB_SETCURSEL, 3, 0);
        } else {
            SendMessageA(GetDlgItem(hwnd, 0x3f0), LB_SETCURSEL, 0, 0);
        }
#if CL_BUILD == 10400
        if ((unsigned char)grim_config_values[84].words[0] == 1) {
            SendMessageA(GetDlgItem(hwnd, 0x3ef), BM_SETCHECK, 1, 0);
        } else {
            SendMessageA(GetDlgItem(hwnd, 0x3ef), BM_SETCHECK, 0, 0);
        }
        if ((unsigned char)grim_config_values[83].words[0] == 1) {
            SendMessageA(GetDlgItem(hwnd, 0x3ee), BM_SETCHECK, 1, 0);
        } else {
            SendMessageA(GetDlgItem(hwnd, 0x3ee), BM_SETCHECK, 0, 0);
        }
#endif
        if (grim_config_values[9].words[0] == 32) {
            SendMessageA(GetDlgItem(hwnd, 0x3eb), BM_SETCHECK, BST_CHECKED, 0);
        } else {
            SendMessageA(GetDlgItem(hwnd, 0x3ea), BM_SETCHECK, BST_CHECKED, 0);
        }
#else
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
#endif
#else
        SendMessageA(GetDlgItem(hwnd, 0x3eb), BM_SETCHECK, BST_CHECKED, 0);
#endif
        return TRUE;
    }

    case WM_COMMAND: {
        unsigned int command = LOWORD(wparam);
        switch (command) {
#if CL_BUILD < 10900
        case 0x3ec:
            if (SendMessageA(GetDlgItem(hwnd, 0x3ec), BM_GETCHECK, 0, 0)) {
                EnableWindow(GetDlgItem(hwnd, 0x3ea), FALSE);
                EnableWindow(GetDlgItem(hwnd, 0x3eb), FALSE);
            } else {
                EnableWindow(GetDlgItem(hwnd, 0x3ea), TRUE);
                EnableWindow(GetDlgItem(hwnd, 0x3eb), TRUE);
            }
            break;
#if CL_BUILD == 10400
        case 0x3ed:
            if (SendMessageA(GetDlgItem(hwnd, 0x3ed), BM_GETCHECK, 0, 0)) {
                EnableWindow(GetDlgItem(hwnd, 0x3ec), TRUE);
            } else {
                EnableWindow(GetDlgItem(hwnd, 0x3ec),
                             *(unsigned int *)&grim_caps_can_render_windowed & 0xff);
            }
            break;
        case 0x3f3:
            if (!HIWORD(wparam)) {
                if (HlinkNavigateString(0, L"http://www.10tons.org/") < 0) {
                    int response =
                        MessageBoxA(0, "Failed to open browser at http://www.10tons.org/",
                                    "Crimsonland", MB_RETRYCANCEL | MB_ICONWARNING);
                    while (response == IDRETRY) {
                        if (HlinkNavigateString(0, L"http://www.10tons.org/") >= 0)
                            break;
                        response = MessageBoxA(
                            0, "Failed to open browser at http://www.10tons.org/",
                            "Crimsonland", MB_RETRYCANCEL | MB_ICONWARNING);
                    }
                }
            }
            break;
        case 0x3f4:
            if (HIWORD(wparam))
                break;
        case 0x3f2:
            if (grim_config_dialog_system_time.wYear <= 2002 &&
                grim_config_dialog_system_time.wMonth < 10) {
                if (HlinkNavigateString(0, L"http://crimsonland.10tons.org/") < 0)
                    MessageBoxA(0,
                                "Failed to open browser at http://crimsonland.10tons.org/",
                                "Crimsonland", MB_ICONWARNING);
            } else {
                if (HlinkNavigateString(0, L"http://www.crimsonland.com/") < 0)
                    MessageBoxA(0, "Failed to open browser at http://www.crimsonland.com/",
                                "Crimsonland", MB_ICONWARNING);
            }
            break;
#endif
        case 0x3e8:
#if CL_BUILD == 10400
            *(bool *)grim_config_values[83].words = SendMessageA(
                GetDlgItem(hwnd, 0x3ee), BM_GETCHECK, 0, 0) != 0;
            *(bool *)grim_config_values[84].words = SendMessageA(
                GetDlgItem(hwnd, 0x3ef), BM_GETCHECK, 0, 0) != 0;
#endif
            grim_config_dialog_bpp16_selected = SendMessageA(
                GetDlgItem(hwnd, 0x3ea), BM_GETCHECK, 0, 0) != 0;
            grim_config_dialog_windowed_selected = SendMessageA(
                GetDlgItem(hwnd, 0x3ec), BM_GETCHECK, 0, 0) != 0;
            grim_config_dialog_pure_software_selected = SendMessageA(
                GetDlgItem(hwnd, 0x3ed), BM_GETCHECK, 0, 0) != 0;
            grim_config_dialog_canceled = false;
#if CL_BUILD >= 10300
            grim_config_resolution_index = SendMessageA(
                GetDlgItem(hwnd, 0x3f0), LB_GETTOPINDEX, 0, 0);
            grim_selected_adapter_index = SendMessageA(
                GetDlgItem(hwnd, 0x3f1), LB_GETTOPINDEX, 0, 0);
#endif
            EndDialog(hwnd, command);
            break;
#else
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
#if CL_BUILD < 10909
            if (HlinkNavigateString(0, L"http://crimsonland.reflexive.com/crimsonland") < 0) {
#else
            if (HlinkNavigateString(0, L"http://www.crimsonland.com") < 0) {
#endif
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

#if CL_BUILD == 10908
        case 0x3e8: {
            // 1.9.8 decodes the selection from its fixed three-mode groups:
            // windowed (only when supported), 16-bit, then 32-bit.
            grim_config_dialog_option_3ef_checked = SendMessageA(
                GetDlgItem(hwnd, 0x3ef), BM_GETCHECK, 0, 0) != 0;
            int selection = SendMessageA(
                GetDlgItem(hwnd, 0x3f9), CB_GETCURSEL, 0, 0);
            if (!grim_caps_can_render_windowed) {
                selection += 3;
            }

            if (selection < 3) {
                grim_windowed_mode_enabled = true;
                grim_config_dialog_windowed_selected = true;
            } else {
                grim_windowed_mode_enabled = false;
                grim_config_dialog_windowed_selected = false;
            }

            int mode = selection % 3;
            if (mode == 0) {
                grim_config_mode_width = 640;
                grim_config_mode_height = 480;
                grim_config_resolution_index = 0;
            } else if (mode == 1) {
                grim_config_mode_width = 800;
                grim_config_mode_height = 600;
                grim_config_resolution_index = 1;
            } else if (mode == 2) {
                grim_config_mode_width = 1024;
                grim_config_mode_height = 768;
                grim_config_resolution_index = 2;
            } else {
                grim_config_mode_width = 800;
                grim_config_mode_height = 600;
                grim_config_resolution_index = 1;
            }

            if (selection >= 3 && selection < 6) {
                grim_config_dialog_bpp16_selected = true;
                grim_config_mode_bpp = 16;
            } else {
                grim_config_dialog_bpp16_selected = false;
                grim_config_mode_bpp = 32;
            }

            grim_config_dialog_canceled = false;
            grim_selected_adapter_index = SendMessageA(
                GetDlgItem(hwnd, 0x3f1), CB_GETCURSEL, 0, 0);
            EndDialog(hwnd, command);
            break;
        }
#else
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

#endif

#endif
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
