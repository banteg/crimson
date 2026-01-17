#ifndef _MINWINDEF_H_
#define _MINWINDEF_H_

typedef unsigned char BYTE;
typedef unsigned short WORD;
typedef unsigned long DWORD;
typedef long LONG;
typedef int BOOL;
typedef int WINBOOL;
typedef unsigned int UINT;
typedef unsigned long ULONG;
typedef unsigned short USHORT;
typedef short SHORT;
typedef int INT;
typedef float FLOAT;
typedef long long LONGLONG;
typedef unsigned long long ULONGLONG;
typedef long LONG_PTR;
typedef unsigned long ULONG_PTR;
typedef DWORD DWORD_PTR;
typedef void *PVOID;
typedef void *LPVOID;
typedef const void *LPCVOID;
typedef char CHAR;
typedef unsigned char UCHAR;
typedef unsigned short WCHAR;
typedef CHAR *LPSTR;
typedef const CHAR *LPCSTR;
typedef WCHAR *LPWSTR;
typedef const WCHAR *LPCWSTR;
typedef DWORD *LPDWORD;
typedef WORD *LPWORD;
typedef BYTE *LPBYTE;
typedef ULONG *PULONG;
typedef ULONG *LPULONG;
typedef LONG *LPLONG;
typedef UINT *LPUINT;

typedef void *HANDLE;
typedef HANDLE HINSTANCE;
typedef HANDLE HMODULE;
typedef HANDLE HWND;
typedef HANDLE HMONITOR;
typedef HANDLE HDC;
typedef HANDLE HICON;
typedef HANDLE HCURSOR;
typedef HANDLE HBRUSH;
typedef HANDLE HFONT;
typedef HANDLE HMENU;
typedef HANDLE HBITMAP;

typedef struct tagRECT {
    LONG left;
    LONG top;
    LONG right;
    LONG bottom;
} RECT, *LPRECT;

typedef const RECT *LPCRECT;

typedef struct _RGNDATAHEADER {
    DWORD dwSize;
    DWORD iType;
    DWORD nCount;
    DWORD nRgnSize;
    RECT rcBound;
} RGNDATAHEADER;

typedef struct _RGNDATA {
    RGNDATAHEADER rdh;
    char Buffer[1];
} RGNDATA, *PRGNDATA, *LPRGNDATA;

typedef struct tagPOINT {
    LONG x;
    LONG y;
} POINT, *LPPOINT;

typedef struct tagSIZE {
    LONG cx;
    LONG cy;
} SIZE, *LPSIZE;

typedef struct tagPALETTEENTRY {
    BYTE peRed;
    BYTE peGreen;
    BYTE peBlue;
    BYTE peFlags;
} PALETTEENTRY, *LPPALETTEENTRY;

typedef LONG HRESULT;
typedef DWORD *LPHRESULT;

typedef struct _LARGE_INTEGER {
    LONG LowPart;
    LONG HighPart;
} LARGE_INTEGER;

typedef struct _FILETIME {
    DWORD dwLowDateTime;
    DWORD dwHighDateTime;
} FILETIME;

#ifndef __GNU_EXTENSION
#define __GNU_EXTENSION
#endif

#ifndef __MSABI_LONG
#define __MSABI_LONG(x) x
#endif

#ifndef WINAPI
#define WINAPI
#endif
#ifndef CALLBACK
#define CALLBACK
#endif

#ifndef MAKE_HRESULT
#define MAKE_HRESULT(sev, fac, code) ((HRESULT)(((unsigned long)(sev) << 31) | ((unsigned long)(fac) << 16) | ((unsigned long)(code))))
#endif

#ifndef SUCCEEDED
#define SUCCEEDED(hr) ((HRESULT)(hr) >= 0)
#endif
#ifndef FAILED
#define FAILED(hr) ((HRESULT)(hr) < 0)
#endif

#ifndef S_OK
#define S_OK ((HRESULT)0L)
#endif
#ifndef E_FAIL
#define E_FAIL ((HRESULT)0x80004005L)
#endif

#ifndef _WAVEFORMATEX_DEFINED
#define _WAVEFORMATEX_DEFINED
typedef struct tWAVEFORMATEX {
    WORD wFormatTag;
    WORD nChannels;
    DWORD nSamplesPerSec;
    DWORD nAvgBytesPerSec;
    WORD nBlockAlign;
    WORD wBitsPerSample;
    WORD cbSize;
} WAVEFORMATEX, *LPWAVEFORMATEX;
#endif

#endif
