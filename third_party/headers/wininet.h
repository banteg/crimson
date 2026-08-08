#ifndef _WININET_H_
#define _WININET_H_

#include <windows.h>

typedef void *HINTERNET;
typedef WORD INTERNET_PORT;

#ifdef __cplusplus
extern "C" {
#endif

HINTERNET WINAPI InternetOpenA(
    LPCSTR agent,
    DWORD accessType,
    LPCSTR proxy,
    LPCSTR proxyBypass,
    DWORD flags);
HINTERNET WINAPI InternetConnectA(
    HINTERNET internet,
    LPCSTR serverName,
    INTERNET_PORT serverPort,
    LPCSTR userName,
    LPCSTR password,
    DWORD service,
    DWORD flags,
    DWORD context);
HINTERNET WINAPI HttpOpenRequestA(
    HINTERNET connection,
    LPCSTR verb,
    LPCSTR objectName,
    LPCSTR version,
    LPCSTR referrer,
    LPCSTR *acceptTypes,
    DWORD flags,
    DWORD context);
BOOL WINAPI HttpSendRequestA(
    HINTERNET request,
    LPCSTR headers,
    DWORD headersLength,
    LPVOID optionalData,
    DWORD optionalLength);
BOOL WINAPI InternetReadFile(
    HINTERNET file,
    LPVOID buffer,
    DWORD bytesToRead,
    LPDWORD bytesRead);
BOOL WINAPI InternetCloseHandle(HINTERNET internet);
BOOL WINAPI InternetGetLastResponseInfoA(
    LPDWORD error,
    LPSTR buffer,
    LPDWORD bufferLength);

#ifdef __cplusplus
}
#endif

#ifndef UNICODE
#define InternetOpen InternetOpenA
#define InternetConnect InternetConnectA
#define HttpOpenRequest HttpOpenRequestA
#define HttpSendRequest HttpSendRequestA
#define InternetGetLastResponseInfo InternetGetLastResponseInfoA
#endif

#endif
