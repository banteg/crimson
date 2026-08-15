#include "grim_texture.h"

extern unsigned int grim_vertex_capacity;
extern IDirect3DVertexBuffer8 *grim_vertex_buffer;
extern IDirect3DIndexBuffer8 *grim_index_buffer;
extern unsigned short *grim_index_write_ptr;
extern unsigned char grim_device_ready;

void grim_release_geometry_buffers(void);

bool grim_create_geometry_buffers(void)
{
    grim_vertex_capacity = 256;
    if (grim_d3d_device->CreateVertexBuffer(
            grim_vertex_capacity * 28,
            0x218,
            0,
            D3DPOOL_SYSTEMMEM,
            &grim_vertex_buffer) < 0) {
        grim_error_text =
            "D3D: Internal: Could not create vertex buffer.";
        return false;
    }

    if (grim_d3d_device->CreateIndexBuffer(
            grim_vertex_capacity * 12,
            0x218,
            D3DFMT_INDEX16,
            D3DPOOL_SYSTEMMEM,
            &grim_index_buffer) < 0) {
        grim_error_text =
            "D3D: Internal: Could not create index buffer.";
        grim_release_geometry_buffers();
        return false;
    }

    if (grim_index_buffer->Lock(
            0,
            0,
            (unsigned char **)&grim_index_write_ptr,
            D3DLOCK_DISCARD) < 0) {
        grim_device_ready = false;
        return false;
    }

    for (unsigned short i = 0;
         i < grim_vertex_capacity;
         i += 4) {
        *grim_index_write_ptr++ = i;
        *grim_index_write_ptr++ = i + 1;
        *grim_index_write_ptr++ = i + 2;
        *grim_index_write_ptr++ = i + 2;
        *grim_index_write_ptr++ = i + 3;
        *grim_index_write_ptr++ = i;
    }

    grim_index_buffer->Unlock();
    grim_d3d_device->SetStreamSource(
        0, grim_vertex_buffer, 28);
    grim_d3d_device->SetIndices(grim_index_buffer, 0);
    return true;
}
