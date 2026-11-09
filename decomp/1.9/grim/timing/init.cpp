#include "grim_timing.h"

void grim_timing_init(void)
{
#if CL_BUILD < 10900
    LARGE_INTEGER frequency;
#if CL_BUILD < 10400
    if (!QueryPerformanceFrequency(&frequency)) {
        frequency.QuadPart = 1000;
    }
#else
    frequency.QuadPart = 1000;
#endif
    grim_ms_to_seconds_scale = 1.0f / frequency.QuadPart;
    grim_read_ticks(grim_timing_epoch_ticks);
    grim_fps = 0.0f;
    grim_frame_dt = 0.0f;
    grim_time_ms = 0.0f;
    grim_time_ticks = 0;
    grim_tick_prev.QuadPart = 0;
    grim_tick_now.QuadPart = 0;
    grim_timing_frozen = 0;
    grim_timing_update();
    grim_tick_prev.QuadPart = grim_tick_now.QuadPart;
    grim_frame_dt = 0.0f;
#else
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
#endif
}
