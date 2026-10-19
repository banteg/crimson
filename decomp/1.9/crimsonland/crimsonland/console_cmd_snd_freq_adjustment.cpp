#include "crimsonland_audio.h"

#if CL_BUILD < 10900
extern "C" unsigned char config_sound_freq_adjustment;
#endif

extern "C" void console_cmd_snd_freq_adjustment(void)
{
#if CL_BUILD < 10900
    unsigned char enabled = !config_sound_freq_adjustment;
    config_sound_freq_adjustment = enabled;
#else
    unsigned char enabled = !config_blob.sound_frequency_adjustment;
    config_blob.sound_frequency_adjustment = enabled;
#endif
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
