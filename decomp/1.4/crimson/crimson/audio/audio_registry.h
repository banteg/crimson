#ifndef FREEWARE_AUDIO_REGISTRY_H
#define FREEWARE_AUDIO_REGISTRY_H

#include "cl_build.h"

extern "C" bool sfx_load_sample(int index, const char *filename);
#if CL_BUILD < 10400
extern "C" void *freeware_sfx_samples[64];
extern "C" signed char __stdcall FSOUND_Sample_SetLoopMode(void *sample, unsigned int mode);
#endif

static __forceinline void load_game_samples()
{
    sfx_load_sample(0, "sounds/hit_01.wav");
    sfx_load_sample(1, "sounds/hit_02.wav");
    sfx_load_sample(3, "sounds/die_01.wav");
    sfx_load_sample(4, "sounds/die_02.wav");
    sfx_load_sample(5, "sounds/die_03.wav");
    sfx_load_sample(6, "sounds/die_02.wav");
    sfx_load_sample(7, "sounds/gunshot_01.wav");
    sfx_load_sample(8, "sounds/plasma_01.wav");
#if CL_BUILD == 10400
    sfx_load_sample(12, "sounds/plasma_02.wav");
#endif
    sfx_load_sample(9, "sounds/attack_01.wav");
    sfx_load_sample(10, "sounds/attack_02.wav");
    sfx_load_sample(11, "sounds/attack_03.wav");
    sfx_load_sample(13, "sounds/wind.wav");
#if CL_BUILD == 10400
    sfx_load_sample(27, "sounds/drip.wav");
    sfx_load_sample(28, "sounds/decay_01.wav");
#endif
    sfx_load_sample(14, "sounds/flamer_01.wav");
    sfx_load_sample(15, "sounds/shotgun_01.wav");
    sfx_load_sample(2, "sounds/pistol_01.wav");
    sfx_load_sample(16, "sounds/gunreload_01.wav");
    sfx_load_sample(17, "sounds/levelup.wav");
    sfx_load_sample(18, "sounds/bonus.wav");
    sfx_load_sample(19, "sounds/berserk.wav");
    sfx_load_sample(26, "sounds/gunburst.wav");
#if CL_BUILD < 10400
    sfx_load_sample(30, "sounds/alqvol.mp3");
    FSOUND_Sample_SetLoopMode(freeware_sfx_samples[30], 2);
#endif
}

#endif
