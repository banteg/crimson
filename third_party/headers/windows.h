#ifndef _WINDOWS_H_
#define _WINDOWS_H_

#include <minwindef.h>
#include <guiddef.h>

#ifndef MB_PRECOMPOSED
#define MB_PRECOMPOSED 0x00000001
#endif
#ifndef IDYES
#define IDYES 6
#endif
#ifndef IDNO
#define IDNO 7
#endif
#ifndef MB_OK
#define MB_OK 0x00000000
#endif
#ifndef MB_YESNO
#define MB_YESNO 0x00000004
#endif
#ifndef ERROR_SUCCESS
#define ERROR_SUCCESS 0L
#endif
#ifndef KEY_ALL_ACCESS
#define KEY_ALL_ACCESS 0x000f003f
#endif
#ifndef HKEY_CURRENT_USER
#define HKEY_CURRENT_USER ((HKEY)(ULONG_PTR)0x80000001)
#endif

#ifdef __cplusplus
extern "C" {
#endif

VOID WINAPI Sleep(DWORD dwMilliseconds);
DWORD WINAPI GetLastError(void);
LPSTR WINAPI GetCommandLineA(void);
int WINAPI GetKeyNameTextA(LONG keyData, LPSTR string, int size);
int WINAPI MessageBoxA(
    HWND hwnd,
    LPCSTR text,
    LPCSTR caption,
    UINT type);
int WINAPI MultiByteToWideChar(
    UINT codePage,
    DWORD flags,
    LPCSTR multiByte,
    int multiByteLength,
    LPWSTR wideChar,
    int wideCharLength);
LONG WINAPI RegCreateKeyExA(
    HKEY key,
    LPCSTR subKey,
    DWORD reserved,
    LPSTR className,
    DWORD options,
    DWORD desiredAccess,
    LPVOID securityAttributes,
    HKEY *result,
    LPDWORD disposition);
LONG WINAPI RegCloseKey(HKEY key);

#ifdef __cplusplus
}
#endif

#endif
