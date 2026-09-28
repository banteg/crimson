#include <windows.h>
#include <string.h>

#include "crimsonland_gameplay.h"

extern HINSTANCE grim_module_handle;
extern HICON grim_window_icon_handle;
extern crimson_cfg_t grim_config_blob;

bool grim_config_blob_save(void);

extern char *grim_parental_lock_enabled_text;
extern char *grim_parental_lock_disabled_text;
extern char grim_parental_password_buffer[256];
extern char grim_parental_password_confirm_buffer[256];

BOOL CALLBACK grim_parental_lock_dialog_proc(
    HWND hwnd, UINT message, WPARAM wparam, LPARAM lparam)
{
    switch (message) {
    case WM_CLOSE:
        EndDialog(hwnd, LOWORD(wparam));
        break;

    case WM_INITDIALOG:
        SendMessageA(hwnd, WM_SETICON, 1, (LPARAM)grim_window_icon_handle);
        SendMessageA(hwnd, WM_SETICON, 0, (LPARAM)grim_window_icon_handle);
        if (grim_config_blob.violence_disabled) {
            SetWindowTextA(
                GetDlgItem(hwnd, 0x40a), grim_parental_lock_enabled_text);
            SendMessageA(
                GetDlgItem(hwnd, 0x400), BM_SETCHECK, 1, 0);
        } else {
            SetWindowTextA(
                GetDlgItem(hwnd, 0x40a), grim_parental_lock_disabled_text);
            SendMessageA(
                GetDlgItem(hwnd, 0x400), BM_SETCHECK, 0, 0);
        }
        return TRUE;

    case WM_COMMAND:
        switch (LOWORD(wparam)) {
        case 0x400:
            if (grim_config_blob.violence_disabled) {
                SendMessageA(
                    GetDlgItem(hwnd, 0x400), BM_SETCHECK, 1, 0);
            } else {
                SendMessageA(
                    GetDlgItem(hwnd, 0x400), BM_SETCHECK, 0, 0);
            }

            if (!grim_config_blob.violence_disabled) {
                DialogBoxParamA(
                    grim_module_handle,
                    MAKEINTRESOURCEA(0x8c),
                    hwnd,
                    grim_parental_lock_dialog_proc,
                    0);
            } else if (!grim_config_blob.player_name_buf[0]) {
                grim_config_blob.violence_disabled = 0;
                grim_config_blob_save();
            } else {
                DialogBoxParamA(
                    grim_module_handle,
                    MAKEINTRESOURCEA(0x8b),
                    hwnd,
                    grim_parental_lock_dialog_proc,
                    0);
            }

            if (grim_config_blob.violence_disabled) {
                SetWindowTextA(
                    GetDlgItem(hwnd, 0x40a),
                    grim_parental_lock_enabled_text);
                SendMessageA(
                    GetDlgItem(hwnd, 0x400), BM_SETCHECK, 1, 0);
            } else {
                SetWindowTextA(
                    GetDlgItem(hwnd, 0x40a),
                    grim_parental_lock_disabled_text);
                SendMessageA(
                    GetDlgItem(hwnd, 0x400), BM_SETCHECK, 0, 0);
            }
            return FALSE;

        case IDCANCEL:
            EndDialog(hwnd, IDCANCEL);
            return FALSE;

        case 0x403:
            EndDialog(hwnd, 0x403);
            return FALSE;

        case 0x408: {
            GetWindowTextA(
                GetDlgItem(hwnd, 0x407),
                grim_parental_password_buffer,
                0xff);

            bool password_matches = true;
            for (unsigned int i = 0;
                 i < strlen(grim_config_blob.player_name_buf);
                 ++i) {
                if (grim_config_blob.player_name_buf[i] !=
                    grim_parental_password_buffer[i]) {
                    password_matches = false;
                }
            }
            if (!password_matches) {
                MessageBoxA(
                    hwnd,
                    "Password is incorrect.\n",
                    "About password",
                    MB_ICONEXCLAMATION);
                return FALSE;
            }

            grim_config_blob.violence_disabled = 0;
            grim_config_blob.player_name_buf[0] = 0;
            grim_config_blob_save();
            EndDialog(hwnd, 0x408);
            return FALSE;
        }

        case 0x409:
            GetWindowTextA(
                GetDlgItem(hwnd, 0x407),
                grim_parental_password_buffer,
                0xff);
            GetWindowTextA(
                GetDlgItem(hwnd, 0x40b),
                grim_parental_password_confirm_buffer,
                0xff);

            if (strcmp(
                    grim_parental_password_buffer,
                    grim_parental_password_confirm_buffer) != 0) {
                MessageBoxA(
                    hwnd,
                    "Given passwords don't match.\n",
                    "About passwords",
                    MB_ICONEXCLAMATION);
                return FALSE;
            }
            if (grim_parental_password_buffer[0] == 0) {
                MessageBoxA(
                    hwnd,
                    "Please give a password.\n",
                    "About password",
                    MB_ICONEXCLAMATION);
                return FALSE;
            }

            memcpy(
                grim_config_blob.player_name_buf,
                grim_parental_password_buffer,
                9);
            grim_config_blob.player_name_buf[8] = 0;
            grim_config_blob.violence_disabled = 1;
            grim_config_blob_save();
            EndDialog(hwnd, 0x409);
            return FALSE;
        }
        break;
    }

    return FALSE;
}
