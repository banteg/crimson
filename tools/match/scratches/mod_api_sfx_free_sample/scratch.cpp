#include "crimsonland_audio.h"
#include "crimsonland_mod_api.h"

unsigned char mod_api_cpp_t::mod_api_sfx_free_sample(int sample_id)
{
    return sfx_release_sample(sample_id);
}
