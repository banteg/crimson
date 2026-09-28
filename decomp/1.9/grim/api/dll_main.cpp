#include <windows.h>

extern HINSTANCE grim_module_handle;
extern HICON grim_window_icon_handle;

BOOL WINAPI DllMain(
    HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
    if (fdwReason == DLL_PROCESS_ATTACH) {
        grim_module_handle = hinstDLL;
        grim_window_icon_handle =
            LoadIconA(hinstDLL, MAKEINTRESOURCEA(0x72));
    }
    return TRUE;
}
