#include <string.h>

#include "crimsonland_audio.h"

extern "C" unsigned char sfx_system_init(void)
{
    if (config_blob.sound_disabled) {
        return 1;
    }

    console_printf(
        &console_log_queue,
        "Initializing Grim SFX sound system\n");
    if (!dsound_init(GetForegroundWindow(), 2, 2, 44100, 16)) {
        console_printf(
            &console_log_queue,
            "...FAILED: unable to init Grim SFX. No sounds used.\n");
        config_blob.sound_disabled = 1;
        config_blob.music_disabled = 1;
        return 0;
    }

    console_printf(&console_log_queue, "...init 44100 Hz 16 bit ok\n");
    console_printf(&console_log_queue, "...using DirectSound output\n");
    console_printf(&console_log_queue, "...using default speaker config\n");
    console_printf(&console_log_queue, "...saying hello to the Ogg!\n");
    memset(sfx_cooldown_table, 0, sizeof(sfx_cooldown_table));
    memset(sfx_voice_table, 0, sizeof(sfx_voice_table));
    console_printf(&console_log_queue, "Init Grim SFX done\n");
    return 1;
}
