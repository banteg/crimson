#include "crimsonland_audio.h"
#include "crimsonland_mod_api.h"

extern "C" int texture_get_or_load(char *name, char *path);

int mod_api_cpp_t::mod_api_gfx_load_texture(char *filename)
{
    char path[260];
    char name[260];

    crt_sprintf(path, "mods\\%s", filename);
    crt_sprintf(name, "CLM_%s", filename);
    return texture_get_or_load(name, path);
}
