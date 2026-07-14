#include "crimsonland_audio.h"

extern "C" void console_cmd_snd_freq_adjustment(void)
{
    unsigned char enabled = !config_blob.sound_frequency_adjustment;
    config_blob.sound_frequency_adjustment = enabled;
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
