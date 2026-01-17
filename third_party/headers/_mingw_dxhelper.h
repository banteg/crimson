#ifndef _MINGW_DXHELPER_H_
#define _MINGW_DXHELPER_H_

#ifndef __MSABI_LONG
#define __MSABI_LONG(x) x
#endif

#ifndef DECL_WINELIB_TYPE_AW
#ifdef UNICODE
#define DECL_WINELIB_TYPE_AW(type) typedef type##W type;
#else
#define DECL_WINELIB_TYPE_AW(type) typedef type##A type;
#endif
#endif

#endif
