#ifndef _URLMON_H_
#define _URLMON_H_

#include <objbase.h>

#ifdef __cplusplus
extern "C" {
#endif

HRESULT WINAPI HlinkNavigateString(IUnknown *site, LPCWSTR target);

#ifdef __cplusplus
}
#endif

#endif
