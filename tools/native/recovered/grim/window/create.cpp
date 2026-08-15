#include <windows.h>

#include "grim_texture.h"

extern HINSTANCE grim_process_hinstance;
extern HICON grim_window_icon_handle;
extern WNDCLASSEXA grim_window_class;
extern char *grim_window_class_name;
extern char *grim_window_title;
extern bool grim_windowed_mode_enabled;
extern unsigned int grim_backbuffer_width;
extern unsigned int grim_backbuffer_height;
extern HWND grim_main_window_hwnd;

LRESULT CALLBACK grim_window_proc(
    HWND hwnd, UINT message, WPARAM wparam, LPARAM lparam);
BOOL grim_window_destroy(void);

bool grim_window_create(void)
{
    if (grim_process_hinstance == 0) {
        grim_process_hinstance = GetModuleHandleA(0);
    }

    grim_window_class.cbSize = sizeof(grim_window_class);
    grim_window_class.style = CS_HREDRAW | CS_VREDRAW;
    grim_window_class.lpfnWndProc = grim_window_proc;
    grim_window_class.cbClsExtra = 0;
    grim_window_class.cbWndExtra = 0;
    grim_window_class.hInstance = grim_process_hinstance;
    grim_window_class.hIcon = grim_window_icon_handle;
    grim_window_class.hCursor = LoadCursorA(0, IDC_ARROW);
    grim_window_class.hbrBackground =
        (HBRUSH)GetStockObject(BLACK_BRUSH);
    grim_window_class.lpszMenuName = 0;
    grim_window_class.lpszClassName = "Crimson";
    grim_window_class.hIconSm = grim_window_icon_handle;
    RegisterClassExA(&grim_window_class);

    if (!grim_windowed_mode_enabled) {
        grim_main_window_hwnd = CreateWindowExA(
            WS_EX_TOPMOST,
            grim_window_class_name,
            grim_window_title,
            WS_POPUP,
            0,
            0,
            GetSystemMetrics(SM_CXSCREEN),
            GetSystemMetrics(SM_CYSCREEN),
            GetDesktopWindow(),
            0,
            grim_process_hinstance,
            0);
    } else {
        int screen_x = GetSystemMetrics(SM_CXSCREEN) / 2;
        int screen_y = GetSystemMetrics(SM_CYSCREEN) / 2;
        RECT rect;
        rect.left = screen_x - grim_backbuffer_width / 2;
        rect.right = screen_x + grim_backbuffer_width / 2;
        rect.top = screen_y - grim_backbuffer_height / 2;
        rect.bottom = screen_y + grim_backbuffer_height / 2;

        AdjustWindowRectEx(
            &rect, 0x00cb0000, FALSE, WS_EX_APPWINDOW);
        grim_main_window_hwnd = CreateWindowExA(
            WS_EX_APPWINDOW,
            grim_window_class_name,
            grim_window_title,
            0x00cb0000,
            rect.left,
            rect.top,
            rect.right - rect.left,
            rect.bottom - rect.top,
            GetDesktopWindow(),
            0,
            grim_process_hinstance,
            0);
    }

    if (grim_main_window_hwnd == 0) {
        grim_error_text = "WIN: Could not create the main window.";
        grim_window_destroy();
        return false;
    }

    ShowWindow(grim_main_window_hwnd, SW_SHOWNORMAL);
    UpdateWindow(grim_main_window_hwnd);
    SetFocus(grim_main_window_hwnd);
    ShowWindow(grim_main_window_hwnd, SW_SHOWNORMAL);
    UpdateWindow(grim_main_window_hwnd);
    return true;
}
