#ifndef _MINGW_UNICODE_H_
#define _MINGW_UNICODE_H_

#ifndef __MINGW_TYPEDEF_AW
#ifdef UNICODE
#define __MINGW_TYPEDEF_AW(type) typedef type##W type;
#else
#define __MINGW_TYPEDEF_AW(type) typedef type##A type;
#endif
#endif

#endif
