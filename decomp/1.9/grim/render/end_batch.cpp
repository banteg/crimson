#include "grim_d3d8.h"
#include "grim2d_cpp.h"

extern unsigned char grim_render_disabled;
extern unsigned char grim_device_ready;
extern unsigned char grim_batch_active;
extern IDirect3DDevice8 *grim_d3d_device;
extern IDirect3DVertexBuffer8 *grim_vertex_buffer;
extern unsigned long grim_vertex_count;

void IGrim2D_cpp::grim_end_batch(void)
{
    if (grim_render_disabled || !grim_batch_active) {
        return;
    }

    grim_vertex_buffer->Unlock();
    if (!grim_device_ready) {
        return;
    }

    unsigned short count = (unsigned short)grim_vertex_count;
    if (count > 0) {
        grim_d3d_device->DrawIndexedPrimitive(
            D3DPT_TRIANGLELIST, 0, count, 0, count >> 1);
    }

    grim_d3d_device->EndScene();
    grim_batch_active = 0;
}
