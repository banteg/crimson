#include "audio_registry.h"
#include "music_tracks.h"
#include "crimsonland_console.h"

extern "C" void freeware_music_create_streams();

extern "C" void freeware_music_load_intro()
{
    if (freeware_audio_disabled)
        return;
#if CL_BUILD == 10300
    sfx_load_sample(29, "sounds/survo41.mp3");
    FSOUND_Sample_SetLoopMode(freeware_sfx_samples[29], 2);
#else
    freeware_music_create_streams();
    if (freeware_music_unavailable)
        return;
    if (freeware_music_tracks[intro_track]->open("music\\survo41.mp3"))
        console_printf(&console_log_queue, "...loading MP3 track 'survo41.mp3' ok\n");
    else
        console_printf(&console_log_queue, "...loading MP3 track 'survo41.mp3' FAILED\n");
#endif
}
