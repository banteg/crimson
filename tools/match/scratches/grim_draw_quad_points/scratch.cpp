#include "grim2d_cpp.h"

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

extern GrimVertex *grim_vertex_write_ptr;
extern GrimDepth grim_vertex_z;
extern unsigned long grim_color_slot0;
extern unsigned long grim_color_slot1;
extern unsigned long grim_color_slot2;
extern unsigned long grim_color_slot3;
extern GrimUV grim_uv_u0[4];
extern unsigned long grim_vertex_count;
extern unsigned int grim_vertex_capacity;

void IGrim2D_cpp::grim_draw_quad_points(
    float x0,
    float y0,
    float x1,
    float y1,
    float x2,
    float y2,
    float x3,
    float y3)
{
    float point[2];

    if (grim_render_disabled || !grim_device_ready) {
        return;
    }

    if (!grim_batch_active) {
        grim_begin_batch();
    }

    point[0] = x0;
    point[1] = y0;
    grim_vertex_write_ptr->position = *(GrimPoint *)&point[0];
    grim_vertex_write_ptr->depth = grim_vertex_z;
    grim_vertex_write_ptr->color = grim_color_slot0;
    grim_vertex_write_ptr->uv = grim_uv_u0[0];
    ++grim_vertex_write_ptr;

    point[0] = x1;
    point[1] = y1;
    grim_vertex_write_ptr->position = *(GrimPoint *)&point[0];
    grim_vertex_write_ptr->depth = grim_vertex_z;
    grim_vertex_write_ptr->color = grim_color_slot1;
    grim_vertex_write_ptr->uv = grim_uv_u0[1];
    ++grim_vertex_write_ptr;

    point[0] = x2;
    point[1] = y2;
    grim_vertex_write_ptr->position = *(GrimPoint *)&point[0];
    grim_vertex_write_ptr->depth = grim_vertex_z;
    grim_vertex_write_ptr->color = grim_color_slot2;
    grim_vertex_write_ptr->uv = grim_uv_u0[2];
    ++grim_vertex_write_ptr;

    point[0] = x3;
    point[1] = y3;
    grim_vertex_write_ptr->position = *(GrimPoint *)&point[0];
    grim_vertex_write_ptr->depth = grim_vertex_z;
    grim_vertex_write_ptr->color = grim_color_slot3;
    grim_vertex_write_ptr->uv = grim_uv_u0[3];
    ++grim_vertex_write_ptr;

    *(unsigned short *)&grim_vertex_count += 4;
    if ((unsigned short)grim_vertex_count >= grim_vertex_capacity) {
        grim_flush_batch();
    }
}
