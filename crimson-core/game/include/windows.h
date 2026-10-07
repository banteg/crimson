#pragma once
#include_next <windows.h>
// The rest of the Win32 surface the recovered Grim reaches; the game module's
// platform layer defines it.
typedef HANDLE HRSRC;
typedef HANDLE HGLOBAL;
#define MAKEINTRESOURCEA(i) ((LPSTR)(ULONG_PTR)(WORD)(i))
#define RT_RCDATA MAKEINTRESOURCEA(10)
#ifdef __cplusplus
extern "C" {
#endif
HMODULE WINAPI GetModuleHandleA(LPCSTR name);
HWND WINAPI GetForegroundWindow(void);
HWND WINAPI GetDesktopWindow(void);
HRSRC WINAPI FindResourceA(HMODULE module, LPCSTR name, LPCSTR type);
HGLOBAL WINAPI LoadResource(HMODULE module, HRSRC resource);
LPVOID WINAPI LockResource(HGLOBAL data);
DWORD WINAPI SizeofResource(HMODULE module, HRSRC resource);
#ifdef __cplusplus
}
#endif
