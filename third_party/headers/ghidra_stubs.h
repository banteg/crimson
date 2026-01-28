#ifndef GHIDRA_STUBS_H
#define GHIDRA_STUBS_H

#ifndef _SIZE_T_DEFINED
#define _SIZE_T_DEFINED
typedef unsigned int size_t;
#endif

#ifndef _UINT_PTR_DEFINED
#define _UINT_PTR_DEFINED
typedef unsigned long UINT_PTR;
#endif

#ifndef _INT_PTR_DEFINED
#define _INT_PTR_DEFINED
typedef long INT_PTR;
#endif

#ifndef _FILE_DEFINED
#define _FILE_DEFINED
typedef struct _IO_FILE FILE;
#endif

#endif
