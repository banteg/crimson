#ifndef FREEWARE_SFX_LOADER_H
#define FREEWARE_SFX_LOADER_H

extern "C" {
bool freeware_sfx_load_library(const char *filename);
void freeware_sfx_unload_library();

extern unsigned char (*freeware_sfx_init)(int frequency, int bits);
extern void (*freeware_sfx_shutdown)();
extern unsigned char (*freeware_sfx_set_paq)(const char *filename);
extern bool (*freeware_sfx_load)(const char *filename, const char *name);
extern void (*freeware_sfx_free)(void *sample);
extern void *(*freeware_sfx_get)(const char *name);
extern int (*freeware_sfx_play)(void *sample, int paused);
extern void (*freeware_sfx_stop_channel)(int channel);
extern signed char (*freeware_sfx_is_playing)(int channel);
extern void (*freeware_sfx_set_paused)(int channel, unsigned char paused);
extern void (*freeware_sfx_set_volume)(int channel, float volume);
extern void (*freeware_sfx_set_pan)(int channel, float pan);
extern void (*freeware_sfx_set_position)(int channel, unsigned int offset);
extern void (*freeware_sfx_set_frequency)(int channel, int frequency);
}

#endif
