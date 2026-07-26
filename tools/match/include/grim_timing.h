#ifndef GRIM_TIMING_H
#define GRIM_TIMING_H

#include <windows.h>
#include <mmsystem.h>

extern float grim_ms_to_seconds_scale;
extern DWORD grim_timing_epoch_ms;
extern float grim_fps;
extern float grim_frame_dt;
extern DWORD grim_time_ms;
extern DWORD grim_tick_prev_ms;
extern DWORD grim_tick_now_ms;
extern unsigned char grim_timing_frozen;
extern DWORD grim_fps_sample_frames;
extern DWORD grim_fps_sample_elapsed_ms;

#endif
