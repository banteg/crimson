#include "grim_timing.h"

void grim_timing_update(void)
{
    grim_tick_prev_ms = grim_tick_now_ms;

    DWORD elapsed_ms;
    do {
        grim_tick_now_ms = timeGetTime();
        elapsed_ms = grim_tick_now_ms - grim_tick_prev_ms;
    } while (elapsed_ms <= 1);

    if (grim_timing_frozen) {
        grim_frame_dt = 0.0f;
        grim_timing_epoch_ms += elapsed_ms;
    } else {
        grim_time_ms += elapsed_ms;
        grim_frame_dt = (float)elapsed_ms * grim_ms_to_seconds_scale;
        ++grim_fps_sample_frames;
        grim_fps_sample_elapsed_ms += elapsed_ms;
    }

    if (grim_fps_sample_elapsed_ms > 500) {
        grim_fps = (float)grim_fps_sample_frames /
            ((float)grim_fps_sample_elapsed_ms * grim_ms_to_seconds_scale);
        grim_fps_sample_frames = 0;
        grim_fps_sample_elapsed_ms -= 500;
    }
}
