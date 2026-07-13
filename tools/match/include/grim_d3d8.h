#ifndef GRIM_D3D8_H
#define GRIM_D3D8_H

// Wine's D3D8 headers use post-VC6 Win32 aliases that are absent from the
// compiler's bundled Platform SDK.
typedef int WINBOOL;
typedef void *HMONITOR;

#include <d3d8.h>

#endif
