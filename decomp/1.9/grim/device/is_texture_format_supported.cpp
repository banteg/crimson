#include "grim_d3d8.h"

extern IDirect3D8 *grim_d3d8;
extern unsigned int grim_selected_adapter_index;
extern D3DDEVTYPE grim_d3d_device_type;
extern D3DFORMAT grim_texture_format;

bool grim_is_texture_format_supported(D3DFORMAT format)
{
    return grim_d3d8->CheckDeviceFormat(
               grim_selected_adapter_index,
               grim_d3d_device_type,
               grim_texture_format,
               0,
               D3DRTYPE_TEXTURE,
               format) >= 0;
}
