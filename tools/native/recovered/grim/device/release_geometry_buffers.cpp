#include "grim_d3d8.h"

extern IDirect3DVertexBuffer8 *grim_vertex_buffer;
extern IDirect3DIndexBuffer8 *grim_index_buffer;

void grim_release_geometry_buffers(void)
{
    if (grim_vertex_buffer != 0) {
        grim_vertex_buffer->Release();
    }
    grim_vertex_buffer = 0;
    if (grim_index_buffer != 0) {
        grim_index_buffer->Release();
    }
    grim_index_buffer = 0;
}
