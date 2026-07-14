#include <string.h>
#include <windows.h>

#include "grim2d_cpp.h"

extern HMODULE grim_dll_module_handle;
extern char grim_dll_name[260];

typedef IGrim2D_cpp *(*grim_get_interface_t)(void);

extern "C" IGrim2D_cpp *grim_load_interface(char *dll_name)
{
    grim_dll_module_handle = LoadLibraryA(dll_name);
    if (grim_dll_module_handle == 0) {
        return 0;
    }

    grim_get_interface_t get_interface =
        (grim_get_interface_t)GetProcAddress(
            grim_dll_module_handle, "GRIM__GetInterface");
    strcpy(grim_dll_name, dll_name);
    if (get_interface == 0) {
        return 0;
    }
    return get_interface();
}
