#include <string.h>
#include <windows.h>
#include <dsound.h>

#include "crimsonland_console.h"
#include "crimsonland_types.h"

extern "C" HMODULE plugin_module_handle;
extern "C" int crt_sprintf(char *dst, const char *format, ...);

struct mod_info_cpp_t {
    char name[0x20];
    char author[0x20];
    float version;
    unsigned int uses_api_version;

    mod_info_cpp_t()
        : version(1.0f), uses_api_version(3)
    {
        memset(name, 0, sizeof(name));
        memset(author, 0, sizeof(author));
    }

    ~mod_info_cpp_t() {}
};

typedef mod_info_cpp_t *(*cmod_get_info_t)(void);

extern "C" mod_info_t *mod_load_info(char *filename)
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

    cmod_get_info_t get_info =
        (cmod_get_info_t)GetProcAddress(
            plugin_module_handle, "CMOD_GetInfo");
    if (get_info == 0) {
        console_printf(&console_log_queue, "CMOD_GetInfo failed.\n");
        FreeLibrary(plugin_module_handle);
        return 0;
    }

    static mod_info_cpp_t info;
    mod_info_cpp_t *result = get_info();
    if (result != 0) {
        info = *result;
    } else {
        console_printf(
            &console_log_queue, "CMOD: bad CMOD_GetInfo function\n");
    }

    FreeLibrary(plugin_module_handle);
    console_printf(&console_log_queue, "CMOD: mod enum '%s'\n", &info);
    return (mod_info_t *)&info;
}
