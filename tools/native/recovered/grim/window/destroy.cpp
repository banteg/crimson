#include <windows.h>

extern HWND grim_main_window_hwnd;
extern HWND grim_device_window_override;
extern HINSTANCE grim_window_class_hinstance;
extern char *grim_window_class_name;

BOOL grim_window_destroy(void)
{
    PostQuitMessage(0);
    if (grim_main_window_hwnd != 0) {
        DestroyWindow(grim_main_window_hwnd);
    }
    if (grim_device_window_override != 0) {
        DestroyWindow(grim_main_window_hwnd);
    }
    return UnregisterClassA(
        grim_window_class_name, grim_window_class_hinstance);
}
