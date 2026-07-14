#include "crimsonland_audio.h"
#include "crimsonland_mod_api.h"

int mod_api_cpp_t::mod_api_sfx_load_sample(char *filename)
{
    char path[260];
    crt_sprintf(path, "mods\\%s", filename);
    return sfx_load_sample(path);
}
