#pragma once
#include_next <windows.h>
// The rest of the Win32 surface the recovered Grim reaches; the game module's
// platform layer defines it.
#define HKEY_LOCAL_MACHINE ((HKEY)(ULONG_PTR)0x80000002)
#define REG_DWORD 4
#define REG_OPTION_RESERVED 0
#ifdef __cplusplus
struct IUnknown;
#endif
typedef int(WINAPI *FARPROC)(void);
typedef HANDLE HRSRC;
typedef HANDLE HGLOBAL;
#define MAKEINTRESOURCEA(i) ((LPSTR)(ULONG_PTR)(WORD)(i))
#define RT_RCDATA MAKEINTRESOURCEA(10)
#ifdef __cplusplus
extern "C" {
#endif
HMODULE WINAPI GetModuleHandleA(LPCSTR name);
HMODULE WINAPI LoadLibraryA(LPCSTR name);
BOOL WINAPI FreeLibrary(HMODULE module);
VOID WINAPI OutputDebugStringA(LPCSTR text);
VOID WINAPI GetLocalTime(LPSYSTEMTIME time);
BOOL WINAPI CreateDirectoryA(LPCSTR path, void *security);
FARPROC WINAPI GetProcAddress(HMODULE module, LPCSTR name);
BOOL WINAPI QueryPerformanceCounter(LARGE_INTEGER *counter);
LONG WINAPI RegQueryValueExA(HKEY key, LPCSTR name, LPDWORD reserved, LPDWORD type, BYTE *data, LPDWORD size);
LONG WINAPI RegSetValueExA(HKEY key, LPCSTR name, DWORD reserved, DWORD type, const BYTE *data, DWORD size);
HWND WINAPI GetForegroundWindow(void);
HWND WINAPI GetDesktopWindow(void);
HRSRC WINAPI FindResourceA(HMODULE module, LPCSTR name, LPCSTR type);
HGLOBAL WINAPI LoadResource(HMODULE module, HRSRC resource);
LPVOID WINAPI LockResource(HGLOBAL data);
DWORD WINAPI SizeofResource(HMODULE module, HRSRC resource);
#ifdef __cplusplus
}
#endif
