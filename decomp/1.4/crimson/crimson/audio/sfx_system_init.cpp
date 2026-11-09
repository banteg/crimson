#include "cl_build.h"
#if CL_BUILD == 10400
#include "../../sfx_loader/sfx_loader.h"
#include "crimsonland_console.h"
#elif CL_BUILD == 10002
#include "audio_registry.h"
#endif
#include <string.h>

extern "C" {
extern unsigned char freeware_audio_disabled;
extern unsigned char audio_resource_pack_available;
extern float sfx_cooldown_table[64];
extern unsigned char freeware_sfx_state[64];
extern void *freeware_sfx_samples[64];

#if CL_BUILD < 10400
float __stdcall FSOUND_GetVersion();
signed char __stdcall FSOUND_SetOutput(int output);
signed char __stdcall FSOUND_SetDriver(int driver);
signed char __stdcall FSOUND_Init(int sample_rate, int channels, unsigned int flags);
#endif
}

extern "C" unsigned char sfx_system_init()
{
#if CL_BUILD >= 10300
    if (freeware_audio_disabled)
        return 1;
#endif

#if CL_BUILD == 10400
    console_printf(&console_log_queue, "Initializing 10ton SFX sound system\n");
    if (!freeware_sfx_load_library("..\\SFX\\Release\\SFX.dll")) {
        console_printf(&console_log_queue, "...DEV SFX not found, trying REL..\n");
        if (!freeware_sfx_load_library("SFX.dll")) {
            console_printf(&console_log_queue, "...FAILED: unable to get 10ton SFX interface.\n");
            return 0;
        }
    }
    console_printf(&console_log_queue, "...interface created\n");
    console_printf(&console_log_queue, "...using DirectSound output\n");
    console_printf(&console_log_queue, "...using default speaker config\n");
    if (!freeware_sfx_init(22050, 16)) {
        console_printf(&console_log_queue, "...init 22050 Hz 16 bit failed\n");
        return 0;
    }
    console_printf(&console_log_queue, "...init 22050 Hz 16 bit ok\n");
    audio_resource_pack_available = freeware_sfx_set_paq("sounds.paq");
    if (audio_resource_pack_available)
        console_printf(&console_log_queue, "...set sound resource paq 'sounds.paq'\n");
    else
        console_printf(&console_log_queue, "...failed to set sound resource paq 'sounds.paq'\n");

#else
#if CL_BUILD == 10002
    const float required_version = 3.4f;
#else
    const float required_version = 3.5f;
#endif
    if (FSOUND_GetVersion() < required_version)
        return 0;

    FSOUND_SetOutput(2); // FSOUND_OUTPUT_DSOUND
    FSOUND_SetDriver(0);
    if (!FSOUND_Init(44100, 32, 1))
        return 0;
#endif

    memset(sfx_cooldown_table, 0, sizeof(sfx_cooldown_table));
    memset(freeware_sfx_state, 0, sizeof(freeware_sfx_state));
    memset(freeware_sfx_samples, 0, sizeof(freeware_sfx_samples));
#if CL_BUILD == 10002
    load_game_samples();
    sfx_load_sample(31, "sounds/3cwonder.mp3");
    FSOUND_Sample_SetLoopMode(freeware_sfx_samples[31], 2);
#elif CL_BUILD == 10400
    console_printf(&console_log_queue, "Init 10ton SFX done\n");
#endif
    return 1;
}
