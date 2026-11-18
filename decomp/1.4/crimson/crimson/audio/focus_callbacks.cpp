#include "cl_build.h"

extern "C" unsigned char freeware_audio_disabled;

#if CL_BUILD == 10300
extern "C" signed char __stdcall FSOUND_SetPaused(int channel, signed char paused);
enum { FSOUND_ALL = -3 };
#else
#include "music_tracks.h"
#endif

extern "C" unsigned char audio_suspend_all()
{
#if CL_BUILD == 10300
    if (!freeware_audio_disabled)
        FSOUND_SetPaused(FSOUND_ALL, 1);
#else
    if (!freeware_music_disabled && !freeware_audio_disabled && !freeware_music_unavailable) {
        freeware_music_tracks[title_track]->pause();
        freeware_music_tracks[game_track]->pause();
        freeware_music_tracks[intro_track]->pause();
    }
#endif
    return 1;
}

extern "C" unsigned char audio_resume_all()
{
#if CL_BUILD == 10300
    if (!freeware_audio_disabled)
        FSOUND_SetPaused(FSOUND_ALL, 0);
#else
    if (!freeware_music_disabled && !freeware_audio_disabled && !freeware_music_unavailable) {
        if (!freeware_music_fading[title_track])
            freeware_music_tracks[title_track]->run();
        if (!freeware_music_fading[game_track])
            freeware_music_tracks[game_track]->run();
        if (!freeware_music_fading[intro_track])
            freeware_music_tracks[intro_track]->run();
    }
#endif
    return 1;
}
