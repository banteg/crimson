#include "crimsonland_audio.h"
#include "crimsonland_mod_api.h"

void mod_api_cpp_t::mod_api_sfx_stop_tune(int tune_id)
{
    music_fade_out_all(tune_id);
}
