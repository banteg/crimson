#include "crimsonland_audio.h"

extern "C" unsigned char audio_resume_all(void)
{
    audio_resume_channels();
    if (cv_verbose->value != 0.0f) {
        console_printf(&console_log_queue, "<-- Restored\n");
    }
    audio_suspend_flag = 0;
    return 1;
}
