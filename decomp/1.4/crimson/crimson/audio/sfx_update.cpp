#include "cl_build.h"
#if CL_BUILD == 10400
#include "../../sfx_loader/sfx_loader.h"
#endif

extern "C" {
extern float sfx_cooldown_table[64];
extern float time_scale_factor;
#if CL_BUILD >= 10300
extern unsigned char freeware_audio_disabled;
#endif
#if CL_BUILD == 10400
extern float frame_dt_copy;
#define cooldown_dt frame_dt_copy
extern unsigned char freeware_music_unavailable, config_sound_freq_adjustment;
void music_update_fades();
#else
extern float frame_dt, freeware_music_volume_a;
#define cooldown_dt frame_dt
extern int freeware_music_channel_a, freeware_music_channel_b;
#if CL_BUILD == 10300
extern float freeware_music_volume_b;
#else
#define freeware_music_volume_b freeware_music_volume_a
#endif
signed char __stdcall FSOUND_StopSound(int channel);
signed char __stdcall FSOUND_SetVolume(int channel, int volume);
signed char __stdcall FSOUND_SetFrequency(int channel, int frequency);
#endif
}

#if CL_BUILD < 10400
static __forceinline bool fade_finished(float &volume)
{
    if (volume < 1.0f)
        volume -= frame_dt * 0.5f;
    if (volume <= 0.0f) {
        volume = 0.0f;
        return true;
    }
    return false;
}

static __forceinline void stop_channel(int &channel)
{
    if (channel != -1)
        FSOUND_StopSound(channel);
    channel = -1;
}
#endif

extern "C" void sfx_update()
{
#if CL_BUILD >= 10300
    if (freeware_audio_disabled)
        return;
#endif

    for (int i = 0; i < 64; ++i) {
        if (sfx_cooldown_table[i] > 0.0f)
            sfx_cooldown_table[i] -= cooldown_dt;
    }

#if CL_BUILD == 10400
    if (!freeware_music_unavailable)
        music_update_fades();
    if (config_sound_freq_adjustment) {
        for (int channel = 0; channel < 1024; ++channel) {
            if (freeware_sfx_is_playing(channel))
                freeware_sfx_set_frequency(channel, (int)(time_scale_factor * 22050.0f));
        }
    }
#else
    if (fade_finished(freeware_music_volume_a)) {
        stop_channel(freeware_music_channel_a);
#if CL_BUILD == 10002
        stop_channel(freeware_music_channel_b);
#endif
    }
#if CL_BUILD == 10300
    if (fade_finished(freeware_music_volume_b))
        stop_channel(freeware_music_channel_b);
#endif

    if (freeware_music_channel_a != -1)
        FSOUND_SetVolume(freeware_music_channel_a, (int)(freeware_music_volume_a * 255.0f));
    if (freeware_music_channel_b != -1)
        FSOUND_SetVolume(freeware_music_channel_b, (int)(freeware_music_volume_b * 255.0f));

    FSOUND_SetFrequency(-3, (int)(time_scale_factor * 22050.0f));
    FSOUND_SetFrequency(freeware_music_channel_a, (int)(time_scale_factor * 44100.0f));
    FSOUND_SetFrequency(freeware_music_channel_b, (int)(time_scale_factor * 44100.0f));
#endif
}
