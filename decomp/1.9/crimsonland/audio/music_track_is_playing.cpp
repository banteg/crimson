#include "crimsonland_audio.h"

extern "C" unsigned char music_track_is_playing(int sfx_id)
{
    if (!music_ready) {
        return 0;
    }
    return music_fade_out_flags[sfx_id] == 0;
}
