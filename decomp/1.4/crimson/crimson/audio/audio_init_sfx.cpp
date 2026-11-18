#include "audio_registry.h"
#include "music_tracks.h"

extern "C" void audio_init_sfx()
{
    if (!freeware_audio_disabled)
        load_game_samples();
}
