#include "audio_registry.h"
#include "music_tracks.h"
#include "crimsonland_console.h"

extern "C" void freeware_audio_load_additional_assets()
{
    if (freeware_audio_disabled)
        return;

    sfx_load_sample(20, "sounds/rocket_01.wav");
    sfx_load_sample(21, "sounds/explo_01.wav");
#if CL_BUILD == 10300
    sfx_load_sample(31, "sounds/3cwonder.mp3");
    FSOUND_Sample_SetLoopMode(freeware_sfx_samples[31], 2);
#else
    if (freeware_music_unavailable)
        return;

    if (freeware_music_tracks[game_track]->open("music\\3cwonder.mp3"))
        console_printf(&console_log_queue, "...loading MP3 track '3cwonder.mp3' ok\n");
    else
        console_printf(&console_log_queue, "...loading MP3 track '3cwonder.mp3' FAILED\n");

    if (freeware_music_tracks[title_track]->open("music\\alqvol.mp3"))
        console_printf(&console_log_queue, "...loading MP3 track 'alqvol.mp3' ok\n");
    else
        console_printf(&console_log_queue, "...loading MP3 track 'alqvol.mp3' FAILED\n");
#endif
}
