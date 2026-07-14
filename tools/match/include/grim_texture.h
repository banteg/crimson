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
    void *backup;

    bool grim_texture_name_equals(char *name);
    void grim_texture_release(void);
};

extern GrimTexture *grim_texture_slots[256];
extern int grim_texture_slot_max_index;

extern "C" int grim_find_texture_by_name(char *name);
extern "C" int grim_find_free_texture_slot(void);
extern "C" int grim_load_texture_internal(char *name, unsigned short *path);
extern "C" int __stdcall D3DXSaveTextureToFileA(
    char *path, int format, IDirect3DBaseTexture8 *texture, void *palette);

#endif
