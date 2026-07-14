#ifndef GRIM_TEXTURE_H
#define GRIM_TEXTURE_H

#include "grim_d3d8.h"

struct GrimTexture {
    char *name;
    IDirect3DTexture8 *texture;
    unsigned char owns_texture;
    unsigned char padding_09[3];
    int width;
    int height;
    IDirect3DSurface8 *backup;

    GrimTexture(char *name);
    ~GrimTexture(void);
    bool grim_texture_name_equals(char *name);
    bool grim_texture_load_file(unsigned short *path);
};

extern GrimTexture *grim_texture_slots[256];
extern int grim_texture_slot_max_index;
extern IDirect3D8 *grim_d3d8;
extern IDirect3DDevice8 *grim_d3d_device;
extern IDirect3DSurface8 *grim_backbuffer_surface;
extern IDirect3DSurface8 *grim_render_target_surface;
extern IDirect3DTexture8 *grim_font_texture;
extern IDirect3DTexture8 *grim_splash_texture;
extern D3DPRESENT_PARAMETERS grim_present_parameters;
extern int grim_present_width;
extern int grim_present_height;
extern D3DFORMAT grim_texture_format;
extern D3DFORMAT grim_preferred_texture_format;
extern char *grim_error_text;

extern "C" int grim_find_texture_by_name(char *name);
extern "C" int grim_find_free_texture_slot(void);
bool grim_is_texture_format_supported(D3DFORMAT format);
bool grim_load_texture_internal(char *name, unsigned short *path);
void grim_release_geometry_buffers(void);
extern "C" int __stdcall D3DXSaveTextureToFileA(
    char *path, int format, IDirect3DBaseTexture8 *texture, void *palette);
extern "C" int __stdcall D3DXSaveSurfaceToFileA(
    char *path,
    int format,
    IDirect3DSurface8 *surface,
    void *palette,
    void *rect);
extern "C" int __stdcall D3DXCreateTexture(
    IDirect3DDevice8 *device,
    unsigned int width,
    unsigned int height,
    unsigned int mip_levels,
    unsigned long usage,
    D3DFORMAT format,
    D3DPOOL pool,
    IDirect3DTexture8 **texture);
extern "C" int __stdcall D3DXCreateTextureFromFileInMemoryEx(
    IDirect3DDevice8 *device,
    const void *source_data,
    unsigned int source_data_size,
    unsigned int width,
    unsigned int height,
    unsigned int mip_levels,
    unsigned long usage,
    D3DFORMAT format,
    D3DPOOL pool,
    unsigned long filter,
    unsigned long mip_filter,
    D3DCOLOR color_key,
    void *source_info,
    PALETTEENTRY *palette,
    IDirect3DTexture8 **texture);
extern "C" int __stdcall d3dx_copy_texture_filtered(
    IDirect3DTexture8 *destination,
    IDirect3DTexture8 *source,
    void *destination_options,
    unsigned long copy_flags,
    unsigned long filter,
    float scale);

#endif
