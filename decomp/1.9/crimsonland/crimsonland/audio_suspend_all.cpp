#include "crimsonland_audio.h"

extern "C" unsigned char audio_suspend_all(void)
{
    audio_suspend_channels();
    if (cv_verbose->value != 0.0f) {
        console_printf(&console_log_queue, "<-- Suspended\n");
    }
    return audio_suspend_flag = 1;
}
