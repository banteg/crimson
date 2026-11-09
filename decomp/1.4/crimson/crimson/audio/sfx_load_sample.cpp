#include "cl_build.h"
#if CL_BUILD == 10400
#include "../../sfx_loader/sfx_loader.h"
#include "crimsonland_console.h"
#endif

extern "C" {
extern unsigned char freeware_audio_disabled;
extern void *freeware_sfx_samples[];
#if CL_BUILD == 10400
extern unsigned char audio_resource_pack_available;
#else
void *__stdcall FSOUND_Sample_Load(int index, const char *filename, unsigned int mode, int length);
signed char __stdcall FSOUND_Sample_SetLoopMode(void *sample, unsigned int mode);
#endif
}

extern "C" bool sfx_load_sample(int index, const char *filename)
{
#if CL_BUILD >= 10300
    if (freeware_audio_disabled)
        return true;
#endif

#if CL_BUILD == 10400
    freeware_sfx_samples[index] = 0;
    if (audio_resource_pack_available) {
        for (const char *p = filename; *p; ++p) {
            if (*p == '/')
                filename = p + 1;
        }
    }
    freeware_sfx_samples[index] = 0;
    if (!freeware_sfx_load(filename, filename)) {
        console_printf(&console_log_queue, "...loading sample '%s' failed\n", filename);
        return false;
    }
    freeware_sfx_samples[index] = freeware_sfx_get(filename);
    console_printf(&console_log_queue, "...loaded sample '%s' to slot %i ok\n", filename, index);
#else
    freeware_sfx_samples[index] = FSOUND_Sample_Load(-2, filename, 0x29, 0);
    if (!freeware_sfx_samples[index])
        return false;
    FSOUND_Sample_SetLoopMode(freeware_sfx_samples[index], 1);
#endif
    return true;
}
