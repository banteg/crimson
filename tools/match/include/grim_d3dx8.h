#ifndef GRIM_D3DX8_H
#define GRIM_D3DX8_H

#include "grim_d3d8.h"

struct GrimD3dxImageInfo {
    unsigned int width;
    unsigned int height;
    unsigned int depth;
    unsigned int mip_levels;
    D3DFORMAT format;
    D3DRESOURCETYPE resource_type;
    unsigned int file_format;
};

extern "C" int __stdcall D3DXCreateTextureFromFileExA(
    IDirect3DDevice8 *device,
    char *path,
    unsigned int width,
    unsigned int height,
    unsigned int mip_levels,
    unsigned long usage,
    D3DFORMAT format,
    D3DPOOL pool,
    unsigned long filter,
    unsigned long mip_filter,
    D3DCOLOR color_key,
    GrimD3dxImageInfo *source_info,
    PALETTEENTRY *palette,
    IDirect3DTexture8 **texture);

#endif
