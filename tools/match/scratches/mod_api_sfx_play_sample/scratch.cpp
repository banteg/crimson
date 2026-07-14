#include "crimsonland_audio.h"
#include "crimsonland_mod_api.h"

void mod_api_cpp_t::mod_api_sfx_play_sample(
    int sample_id, float pan, float volume)
{
    float position[2];
    position[0] = pan * 512.0f;
    position[1] = 0.0f;
    sfx_play_panned(sample_id, position, volume);
}
