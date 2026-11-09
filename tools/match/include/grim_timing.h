#ifndef GRIM_TIMING_H
#define GRIM_TIMING_H

#include "cl_build.h"
#include <windows.h>
#include <mmsystem.h>

extern float grim_ms_to_seconds_scale;
extern float grim_fps;
extern float grim_frame_dt;
extern unsigned char grim_timing_frozen;
extern DWORD grim_fps_sample_frames;
#if CL_BUILD < 10900
extern LARGE_INTEGER grim_timing_epoch_ticks;
extern LARGE_INTEGER grim_tick_prev;
extern LARGE_INTEGER grim_tick_now;
extern __int64 grim_time_ticks;
extern float grim_time_ms;
extern float grim_fps_sample_seconds;
void grim_timing_update(void);

inline void grim_read_ticks(LARGE_INTEGER &ticks)
{
#if CL_BUILD < 10400
    if (QueryPerformanceCounter(&ticks)) {
        return;
    }
#endif
    ticks.QuadPart = timeGetTime();
}

#else
extern DWORD grim_timing_epoch_ms;
extern DWORD grim_time_ms;
extern DWORD grim_tick_prev_ms;
extern DWORD grim_tick_now_ms;
extern DWORD grim_fps_sample_elapsed_ms;
#endif

#endif
