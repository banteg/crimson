#ifndef _GUIDDEF_H_
#define _GUIDDEF_H_

#include <minwindef.h>

typedef struct _GUID {
    DWORD Data1;
    WORD Data2;
    WORD Data3;
    BYTE Data4[8];
} GUID;

typedef GUID IID;
typedef GUID CLSID;

typedef const GUID *REFGUID;
typedef const IID *REFIID;
typedef GUID *LPGUID;
typedef const GUID *LPCGUID;

#ifndef DEFINE_GUID
#define DEFINE_GUID(name, l, w1, w2, b1, b2, b3, b4, b5, b6, b7, b8) \
    const GUID name = {l, w1, w2, {b1, b2, b3, b4, b5, b6, b7, b8}}
#endif

#ifndef GUID_NULL
static const GUID GUID_NULL = {0, 0, 0, {0, 0, 0, 0, 0, 0, 0, 0}};
#endif

#endif
