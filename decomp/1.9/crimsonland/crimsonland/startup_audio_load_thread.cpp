#include "crimsonland_audio.h"

extern "C" {
extern unsigned char startup_intro_enabled;
extern unsigned char startup_async_load_ready;

void crt_endthread(void);
}

extern "C" void startup_audio_load_thread(void *unused)
{
    console_printf(
        &console_log_queue,
        "beginthread () - (Sound library)\n");
    audio_init_music();
    audio_init_sfx();
    startup_intro_enabled = 1;
    startup_async_load_ready = 1;
    console_printf(
        &console_log_queue,
        "endthread () - (Sound library)\n");
    crt_endthread();
}
