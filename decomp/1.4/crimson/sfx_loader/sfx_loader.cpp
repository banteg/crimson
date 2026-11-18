#include <windows.h>
#include "sfx_loader.h"

extern "C" HMODULE freeware_sfx_module;

template <class Function>
static inline void bind_export(Function &slot, const char *name)
{
    slot = (Function)GetProcAddress(freeware_sfx_module, name);
}

extern "C" bool freeware_sfx_load_library(const char *filename)
{
    freeware_sfx_module = LoadLibraryA(filename);
    if (!freeware_sfx_module)
        return false;

    bind_export(freeware_sfx_init, "SFX_Init");
    bind_export(freeware_sfx_shutdown, "SFX_Shutdown");
    bind_export(freeware_sfx_set_paq, "SFX_SetPaq");
    bind_export(freeware_sfx_load, "SFX_LoadSfx");
    bind_export(freeware_sfx_free, "SFX_FreeSfx");
    bind_export(freeware_sfx_get, "SFX_GetSfx");
    bind_export(freeware_sfx_play, "SFX_PlaySfx");
    bind_export(freeware_sfx_stop_channel, "SFX_StopChannel");
    bind_export(freeware_sfx_is_playing, "SFX_IsPlaying");
    bind_export(freeware_sfx_set_paused, "SFX_SetChannelPaused");
    bind_export(freeware_sfx_set_volume, "SFX_SetChannelVolume");
    bind_export(freeware_sfx_set_pan, "SFX_SetChannelPan");
    bind_export(freeware_sfx_set_position, "SFX_SetChannelPosition");
    bind_export(freeware_sfx_set_frequency, "SFX_SetChannelFrequency");
    return true;
}

extern "C" void freeware_sfx_unload_library()
{
    FreeLibrary(freeware_sfx_module);
}
