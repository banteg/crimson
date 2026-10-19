#include "crimsonland_audio.h"

extern "C" unsigned char config_sound_freq_adjustment;

extern "C" void console_cmd_snd_freq_adjustment(void)
{
    unsigned char enabled = !config_sound_freq_adjustment;
    config_sound_freq_adjustment = enabled;
    if (enabled) {
        console_printf(
            &console_log_queue,
            "Sound frequency adjustment is now enabled.\n");
        return;
    }

    console_printf(
        &console_log_queue,
        "Sound frequency adjustment is now disabled.\n");
}
