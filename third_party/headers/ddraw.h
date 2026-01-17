#ifndef _DDRAW_H_
#define _DDRAW_H_

#include <minwindef.h>

typedef struct _DDPIXELFORMAT {
    DWORD dwSize;
    DWORD dwFlags;
    DWORD dwFourCC;
    DWORD dwRGBBitCount;
    DWORD dwRBitMask;
    DWORD dwGBitMask;
    DWORD dwBBitMask;
    DWORD dwRGBAlphaBitMask;
} DDPIXELFORMAT, *LPDDPIXELFORMAT;

typedef struct _DDSURFACEDESC {
    DWORD dwSize;
    DWORD dwFlags;
    DWORD dwHeight;
    DWORD dwWidth;
    LONG lPitch;
    DWORD dwBackBufferCount;
    DWORD dwMipMapCount;
    DWORD dwAlphaBitDepth;
    DWORD dwReserved;
    LPVOID lpSurface;
    DDPIXELFORMAT ddpfPixelFormat;
} DDSURFACEDESC, *LPDDSURFACEDESC;

#endif
