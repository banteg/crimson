#include "grim_timing.h"

void grim_timing_init(void)
{
    grim_ms_to_seconds_scale = 0.001f;

    DWORD now = timeGetTime();
    grim_timing_epoch_ms = now;
    grim_fps = 0.0f;
    grim_frame_dt = 0.0f;
    grim_time_ms = 0;
    grim_tick_prev_ms = now;
    grim_tick_now_ms = now;
    grim_timing_frozen = 0;

    timeBeginPeriod(1);
}
