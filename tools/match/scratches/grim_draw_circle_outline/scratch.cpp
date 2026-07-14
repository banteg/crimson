#include <string.h>

#include "grim_d3d8.h"
#include "grim2d_cpp.h"

extern "C" double cos(double angle);
extern "C" double sin(double angle);

struct GrimCircleVertex {
    float x;
    float y;
    float z;
    float rhw;
    unsigned long color;
    float u;
    float v;
};

extern unsigned char grim_device_ready;
extern unsigned char grim_batch_active;
extern IDirect3DDevice8 *grim_d3d_device;
extern IDirect3DVertexBuffer8 *grim_vertex_buffer;
extern GrimCircleVertex *grim_vertex_write_ptr;
extern unsigned long grim_vertex_count;
extern float grim_vertex_z;
extern float grim_vertex_rhw;
extern unsigned long grim_color_slot0;
extern float grim_uv_u0;
extern float grim_uv_v0;

void IGrim2D_cpp::grim_draw_circle_outline(float x, float y, float radius)
{
    if (grim_batch_active) {
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
            (unsigned char **)&grim_vertex_write_ptr,
            D3DLOCK_DISCARD | D3DLOCK_NOSYSLOCK) < 0) {
        grim_device_ready = 0;
    }

    *(unsigned short *)&grim_vertex_count = 0;
    GrimCircleVertex vertex;
    vertex.z = grim_vertex_z;
    vertex.rhw = grim_vertex_rhw;
    vertex.color = grim_color_slot0;
    vertex.u = grim_uv_u0;
    vertex.v = grim_uv_v0;

    int segment_count = (int)(radius * 0.2f + 14.0f);
    int segment = 0;
    if (segment_count >= 0) {
        double segment_divisor = segment_count;
        do {
            double angle = segment * 6.2831855f / segment_divisor;
            float cosine = (float)cos(angle);
            vertex.x = cosine * radius + x;
            float sine = (float)sin(angle);
            vertex.y = sine * radius + y;
            vertex.v = 0.0f;
            memcpy(grim_vertex_write_ptr, &vertex, 0x1c);
            ++grim_vertex_write_ptr;
            ++*(unsigned short *)&grim_vertex_count;

            vertex.x = (radius + 2.0f) * cosine + x;
            vertex.y = (radius + 2.0f) * sine + y;
            vertex.v = 1.0f;
            memcpy(grim_vertex_write_ptr, &vertex, 0x1c);
            ++grim_vertex_write_ptr;
            ++*(unsigned short *)&grim_vertex_count;
            ++segment;
        } while (segment <= segment_count);
    }

    grim_vertex_buffer->Unlock();
    if (!grim_device_ready) {
        return;
    }

    grim_d3d_device->DrawPrimitive(
        D3DPT_TRIANGLESTRIP,
        0,
        (unsigned short)grim_vertex_count - 2);
    grim_d3d_device->EndScene();
    grim_batch_active = 0;
}
