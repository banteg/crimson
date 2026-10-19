#include "grim_d3d8.h"
#include "grim2d_cpp.h"

extern unsigned char grim_render_disabled;
extern unsigned char grim_device_ready;
extern unsigned char grim_batch_active;
extern IDirect3DDevice8 *grim_d3d_device;
extern IDirect3DVertexBuffer8 *grim_vertex_buffer;
#if CL_BUILD < 10400
extern IDirect3DIndexBuffer8 *grim_index_buffer;
#endif
#if CL_BUILD < 10900
extern unsigned short grim_vertex_count;
#else
extern unsigned long grim_vertex_count;
#endif

void IGrim2D_cpp::grim_end_batch(void)
{
#if CL_BUILD < 10400
    if (!grim_batch_active) {
        return;
    }
#else
    if (grim_render_disabled || !grim_batch_active) {
        return;
    }
#endif

    grim_vertex_buffer->Unlock();
#if CL_BUILD < 10400
    grim_index_buffer->Unlock();
#endif
    if (!grim_device_ready) {
        return;
    }

#if CL_BUILD < 10900
    if (grim_vertex_count > 0) {
        grim_d3d_device->DrawIndexedPrimitive(
            D3DPT_TRIANGLELIST, 0, grim_vertex_count, 0, grim_vertex_count >> 1);
    }
#else
    unsigned short count = (unsigned short)grim_vertex_count;
    if (count > 0) {
        grim_d3d_device->DrawIndexedPrimitive(
            D3DPT_TRIANGLELIST, 0, count, 0, count >> 1);
    }
#endif

    grim_d3d_device->EndScene();
    grim_batch_active = 0;
}
