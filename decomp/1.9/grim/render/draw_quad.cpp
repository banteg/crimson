#include "grim2d_cpp.h"
#if CL_BUILD < 10400
#include <math.h>
#include "grim_d3d8.h"
#endif

struct GrimPoint {
    float x;
    float y;
};

struct GrimDepth {
    float z;
    float rhw;
};

struct GrimUV {
    float u;
    float v;
};

struct GrimVertex {
    GrimPoint position;
    GrimDepth depth;
    unsigned long color;
    GrimUV uv;
};

typedef char GrimVertex_size_must_be_28[(sizeof(GrimVertex) == 28) ? 1 : -1];

extern unsigned char grim_render_disabled;
extern unsigned char grim_device_ready;
extern unsigned char grim_batch_active;

extern float grim_rotation_radians;
extern float grim_rotation_cos;
extern float grim_rotation_sin;

extern GrimVertex *grim_vertex_write_ptr;
extern GrimDepth grim_vertex_z;
extern unsigned long grim_color_slot0;
extern unsigned long grim_color_slot1;
extern unsigned long grim_color_slot2;
extern unsigned long grim_color_slot3;
extern GrimUV grim_uv_u0[4];
#if CL_BUILD < 10900
extern unsigned short grim_vertex_count;
#else
extern unsigned long grim_vertex_count;
#endif
extern unsigned int grim_vertex_capacity;
#if CL_BUILD < 10400
extern IDirect3DDevice8 *grim_d3d_device;
extern IDirect3DVertexBuffer8 *grim_vertex_buffer;
extern IDirect3DIndexBuffer8 *grim_index_buffer;
extern unsigned short *grim_index_write_ptr;
#endif

inline float grim_inverse_sqrt(float number)
{
    float half = number * 0.5f;
    float estimate = number;
    long bits = *(long *)&estimate;
    bits = 0x5f3759df - (bits >> 1);
    estimate = *(float *)&bits;
    estimate = estimate * (1.5f - half * estimate * estimate);
    return estimate;
}

void IGrim2D_cpp::grim_draw_quad(float x, float y, float w, float h)
{
#if CL_BUILD == 10908
    // 1.9.8 keeps the quad centre out of the corner array, so its frame is
    // four points (0x20) where 1.9.93 reserves five (0x28).
    float points[4][2];
    float center[2];
#else
    float points[5][2];
    float *center = points[4];
#endif

#if CL_BUILD < 10400
    if (!grim_device_ready) {
        return;
    }
#else
    if (grim_render_disabled || !grim_device_ready) {
        return;
    }
#endif

    if (!grim_batch_active) {
        grim_begin_batch();
    }

    if (grim_rotation_radians == 0.0f) {
        points[0][0] = x;
        points[0][1] = y;
        points[1][0] = x + w;
        points[1][1] = y;
        points[2][0] = points[1][0];
        points[2][1] = y + h;
        points[3][0] = x;
        points[3][1] = points[2][1];
    } else {
        center[0] = x + w * 0.5f;
        center[1] = y + h * 0.5f;
#if CL_BUILD < 10400
        float half_diagonal = (float)sqrt(w * w + h * h) * 0.5f;
#else
        float length_sq = w * w + h * h;
        float half_diagonal = length_sq * grim_inverse_sqrt(length_sq) * 0.5f;
#endif
        float dx = grim_rotation_cos * half_diagonal;
        half_diagonal *= grim_rotation_sin;

        points[0][0] = center[0] - dx;
        points[0][1] = center[1] - half_diagonal;
        points[1][0] = center[0];
        points[1][0] += half_diagonal;
        float neg_dx = -dx;
        points[1][1] = neg_dx + center[1];
        points[2][0] = center[0];
        points[2][0] += dx;
        points[2][1] = center[1];
        points[2][1] += half_diagonal;
        half_diagonal = -half_diagonal;
        points[3][0] = half_diagonal + center[0];
        points[3][1] = center[1];
        points[3][1] += dx;
    }

    grim_vertex_write_ptr->position = *(GrimPoint *)&points[0][0];
    grim_vertex_write_ptr->depth = grim_vertex_z;
    grim_vertex_write_ptr->color = grim_color_slot0;
    grim_vertex_write_ptr->uv = grim_uv_u0[0];
    ++grim_vertex_write_ptr;

    grim_vertex_write_ptr->position = *(GrimPoint *)&points[1][0];
    grim_vertex_write_ptr->depth = grim_vertex_z;
    grim_vertex_write_ptr->color = grim_color_slot1;
    grim_vertex_write_ptr->uv = grim_uv_u0[1];
    ++grim_vertex_write_ptr;

    grim_vertex_write_ptr->position = *(GrimPoint *)&points[2][0];
    grim_vertex_write_ptr->depth = grim_vertex_z;
    grim_vertex_write_ptr->color = grim_color_slot2;
    grim_vertex_write_ptr->uv = grim_uv_u0[2];
    ++grim_vertex_write_ptr;

    grim_vertex_write_ptr->position = *(GrimPoint *)&points[3][0];
    grim_vertex_write_ptr->depth = grim_vertex_z;
    grim_vertex_write_ptr->color = grim_color_slot3;
    grim_vertex_write_ptr->uv = grim_uv_u0[3];
    ++grim_vertex_write_ptr;

#if CL_BUILD < 10400
    *grim_index_write_ptr++ = grim_vertex_count;
    *grim_index_write_ptr++ = grim_vertex_count + 1;
    *grim_index_write_ptr++ = grim_vertex_count + 2;
    *grim_index_write_ptr++ = grim_vertex_count + 2;
    *grim_index_write_ptr++ = grim_vertex_count + 3;
    *grim_index_write_ptr++ = grim_vertex_count;
#endif
#if CL_BUILD < 10900
    grim_vertex_count += 4;
    if (grim_vertex_count >= grim_vertex_capacity) {
#if CL_BUILD < 10300
        grim_vertex_buffer->Unlock();
        grim_index_buffer->Unlock();
        grim_d3d_device->DrawIndexedPrimitive(
            D3DPT_TRIANGLELIST, 0, grim_vertex_count, 0, grim_vertex_count >> 1);
        if (grim_vertex_buffer->Lock(
                0,
                0,
                (unsigned char **)&grim_vertex_write_ptr,
                D3DLOCK_DISCARD | D3DLOCK_NOSYSLOCK) >= 0) {
            if (grim_index_buffer->Lock(
                    0,
                    0,
                    (unsigned char **)&grim_index_write_ptr,
                    D3DLOCK_DISCARD | D3DLOCK_NOSYSLOCK) >= 0) {
                grim_vertex_count = 0;
            }
        }
#else
        grim_flush_batch();
#endif
    }
#else
    *(unsigned short *)&grim_vertex_count += 4;
    if ((unsigned short)grim_vertex_count >= grim_vertex_capacity) {
        grim_flush_batch();
    }
#endif
}
