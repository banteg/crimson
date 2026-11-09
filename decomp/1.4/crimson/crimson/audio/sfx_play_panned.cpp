#include "cl_build.h"
#if CL_BUILD == 10400
#include "../../sfx_loader/sfx_loader.h"
#endif

extern "C" {
extern float sfx_cooldown_table[];
extern void *freeware_sfx_samples[];
#if CL_BUILD >= 10300
extern unsigned char freeware_audio_disabled;
#endif
#if CL_BUILD == 10400
extern unsigned char freeware_game_active;
#else
int __stdcall FSOUND_PlaySoundEx(int channel, void *sample, void *dsp, signed char paused);
signed char __stdcall FSOUND_SetVolume(int channel, int volume);
signed char __stdcall FSOUND_SetPan(int channel, int pan);
signed char __stdcall FSOUND_SetPaused(int channel, signed char paused);
#endif
}

extern "C" int sfx_play_panned(int sample, float volume, float pan)
{
#if CL_BUILD == 10400
    if (!freeware_game_active && sample < 13)
        return -1;
    if (!freeware_sfx_samples[sample])
        return -1;
#endif
#if CL_BUILD >= 10300
    if (freeware_audio_disabled)
        return -1;
#endif
    if (sfx_cooldown_table[sample] > 0.0f)
        return -1;
#if CL_BUILD == 10400
    if (sample == 14)
        sfx_cooldown_table[sample] = 0.58f;
    else
        sfx_cooldown_table[sample] = 0.08f;

    int channel = freeware_sfx_play(freeware_sfx_samples[sample], 0);
    freeware_sfx_set_volume(channel, (volume + 4.0f) * (1.0f / 6.0f));
#else
    sfx_cooldown_table[sample] = 0.08f;
    int channel = FSOUND_PlaySoundEx(-1, freeware_sfx_samples[sample], 0, 1);
    FSOUND_SetVolume(channel, (int)(volume * 255.0f));
    FSOUND_SetPan(channel, (int)(pan * 255.0f));
    FSOUND_SetPaused(channel, 0);
#endif
    return channel;
}
