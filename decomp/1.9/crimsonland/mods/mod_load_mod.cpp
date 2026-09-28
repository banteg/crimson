#include <windows.h>

#include "crimsonland_console.h"
#include "crimsonland_mod_api.h"

extern "C" HMODULE plugin_module_handle;
extern mod_api_cpp_t mod_api_context;

extern "C" int crt_sprintf(char *dst, const char *format, ...);

typedef mod_interface_cpp_t *(*cmod_get_mod_t)(void);

extern "C" mod_interface_cpp_t *mod_load_mod(char *filename)
{
    char lib_filename[512];
    crt_sprintf(lib_filename, "mods\\%s", filename);
    console_printf(&console_log_queue, "CMOD: '%s'\n", lib_filename);

    plugin_module_handle = LoadLibraryA(lib_filename);
    if (plugin_module_handle == 0) {
        console_printf(
            &console_log_queue, "CMOD: Load library failed.\n");
        return 0;
    }

    cmod_get_mod_t get_mod =
        (cmod_get_mod_t)GetProcAddress(plugin_module_handle, "CMOD_GetMod");
    if (get_mod == 0) {
        console_printf(
            &console_log_queue, "CMOD: CMOD_GetMod failed.\n");
        FreeLibrary(plugin_module_handle);
        return 0;
    }

    mod_interface_cpp_t *mod = get_mod();
    if (mod != 0) {
        mod->api = &mod_api_context;
    } else {
        console_printf(
            &console_log_queue, "CMOD: bad CMOD_GetMod function\n");
    }

    console_printf(&console_log_queue, "CMOD_GetMod ok\n");
    return mod;
}
