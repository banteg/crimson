#pragma once
#include <windows.h>
// The multimedia timer the recovered Grim reads; the platform layer supplies it.
#ifdef __cplusplus
extern "C" {
#endif
DWORD WINAPI timeGetTime(void);
UINT WINAPI timeBeginPeriod(UINT period);
UINT WINAPI timeEndPeriod(UINT period);
#ifdef __cplusplus
}
#endif
