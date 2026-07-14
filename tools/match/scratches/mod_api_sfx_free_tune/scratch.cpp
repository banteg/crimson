#include "crimsonland_audio.h"
#include "crimsonland_mod_api.h"

unsigned char mod_api_cpp_t::mod_api_sfx_free_tune(int tune_id)
{
    return music_release_track(tune_id);
}
