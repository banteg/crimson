#ifndef GRIM_D3D8_H
#define GRIM_D3D8_H

// Wine's D3D8 headers use post-VC6 Win32 aliases that are absent from the
// compiler's bundled Platform SDK.
typedef int WINBOOL;
typedef void *HMONITOR;

// Wine gates its D3D8 pack(4) wrapper on __i386__, which VC6 does not define.
// Apply the native Win32 DirectX ABI explicitly around the imported header.
#pragma pack(push, 4)
#include <d3d8.h>
#pragma pack(pop)

#endif
