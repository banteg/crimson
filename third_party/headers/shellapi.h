#ifndef _SHELLAPI_H_
#define _SHELLAPI_H_

#include <windows.h>

#ifndef SW_SHOWNORMAL
#define SW_SHOWNORMAL 1
#endif

#ifdef __cplusplus
extern "C" {
#endif

HINSTANCE WINAPI ShellExecuteA(
    HWND hwnd,
    LPCSTR operation,
    LPCSTR file,
    LPCSTR parameters,
    LPCSTR directory,
    INT showCommand);

#ifdef __cplusplus
}
#endif

#ifndef UNICODE
#define ShellExecute ShellExecuteA
#endif

#endif
