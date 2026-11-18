#include "cl_build.h"
#if CL_BUILD == 10400
#include "../../sfx_loader/sfx_loader.h"
#include "crimsonland_console.h"
#endif

extern "C" {
extern unsigned char freeware_audio_disabled;
#if CL_BUILD < 10400
extern void *freeware_sfx_samples[64];
void __stdcall FSOUND_Sample_Free(void *sample);
void __stdcall FSOUND_Close();
#endif
}

extern "C" void audio_shutdown_all()
{
#if CL_BUILD >= 10300
    if (freeware_audio_disabled)
        return;
#endif

#if CL_BUILD == 10400
    console_printf(&console_log_queue, "SFX_Shutdown ()\n");
    freeware_sfx_shutdown();
    freeware_sfx_unload_library();
    console_printf(&console_log_queue, "SFX Released.\n");
    console_log_queue.flush_log("console.log");
#else
    for (int i = 0; i < 64; ++i) {
        if (freeware_sfx_samples[i])
            FSOUND_Sample_Free(freeware_sfx_samples[i]);
    }
    FSOUND_Close();
#endif
}
