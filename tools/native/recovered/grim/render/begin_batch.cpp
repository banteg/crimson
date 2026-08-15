#include "grim_d3d8.h"
#include "grim2d_cpp.h"

extern unsigned char grim_render_disabled;
extern unsigned char grim_device_ready;
extern unsigned char grim_batch_active;
extern IDirect3DDevice8 *grim_d3d_device;
extern IDirect3DVertexBuffer8 *grim_vertex_buffer;
extern unsigned char *grim_vertex_write_ptr;
extern unsigned long grim_vertex_count;

void IGrim2D_cpp::grim_begin_batch(void)
{
    if (grim_render_disabled || grim_batch_active) {
        return;
    }

    grim_batch_active = 1;
    if (!grim_device_ready) {
        return;
    }

    grim_d3d_device->BeginScene();
    if (grim_vertex_buffer->Lock(
            0,
            0,
            &grim_vertex_write_ptr,
            D3DLOCK_DISCARD | D3DLOCK_NOSYSLOCK) < 0) {
        grim_device_ready = 0;
    }
    *(unsigned short *)&grim_vertex_count = 0;
}
