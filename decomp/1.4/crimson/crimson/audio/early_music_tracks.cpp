#include "cl_build.h"

extern "C" {
extern int freeware_music_channel_a, freeware_music_channel_b;
extern float freeware_music_volume_a;
#if CL_BUILD == 10300
extern float freeware_music_volume_b;
extern unsigned char freeware_music_disabled, freeware_audio_disabled;
#endif
int sfx_play_panned(int sample, float volume, float pan);
signed char __stdcall FSOUND_StopSound(int channel);
}

extern "C" void freeware_title_track_start(int sample)
{
#if CL_BUILD == 10002
    if (freeware_music_volume_a < 1.0f) {
        freeware_music_volume_a = 0.0f;
        if (freeware_music_channel_a != -1)
            FSOUND_StopSound(freeware_music_channel_a);
        freeware_music_channel_a = -1;
        if (freeware_music_channel_b != -1)
            FSOUND_StopSound(freeware_music_channel_b);
        freeware_music_channel_b = -1;
    }
#else
    if (freeware_music_channel_a != -1 && freeware_music_volume_a == 1.0f)
        return;
    if (freeware_audio_disabled || freeware_music_disabled)
        return;
    freeware_music_volume_a = 0.0f;
    if (freeware_music_channel_a != -1)
        FSOUND_StopSound(freeware_music_channel_a);
    freeware_music_channel_a = -1;
#endif
    freeware_music_channel_a = sfx_play_panned(sample, 1.0f, 0.5f);
    freeware_music_volume_a = 1.0f;
}

extern "C" void freeware_game_track_start(int sample)
{
#if CL_BUILD == 10002
    if (freeware_music_channel_a != -1)
        FSOUND_StopSound(freeware_music_channel_a);
#else
    if (freeware_music_channel_b != -1 && freeware_music_volume_b == 1.0f)
        return;
    if (freeware_music_disabled || freeware_audio_disabled)
        return;
#endif
    if (freeware_music_channel_b != -1)
        FSOUND_StopSound(freeware_music_channel_b);
#if CL_BUILD == 10002
    freeware_music_channel_a = -1;
#else
    freeware_music_channel_b = -1;
#endif
    freeware_music_channel_b = sfx_play_panned(sample, 1.0f, 0.5f);
#if CL_BUILD == 10002
    freeware_music_volume_a = 1.0f;
#else
    freeware_music_volume_b = 1.0f;
#endif
}

extern "C" void freeware_title_track_fade()
{
    freeware_music_volume_a = 0.991f;
}

#if CL_BUILD == 10300
extern "C" void freeware_game_track_fade()
{
    freeware_music_volume_b = 0.991f;
}
#endif
