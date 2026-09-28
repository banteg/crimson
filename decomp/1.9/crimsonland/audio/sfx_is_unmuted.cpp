#include "crimsonland_audio.h"

extern "C" unsigned char sfx_is_unmuted(int sfx_id)
{
    if (!sfx_unmuted_flag) {
        return 0;
    }
    return sfx_mute_flags[sfx_id] == 0;
}
