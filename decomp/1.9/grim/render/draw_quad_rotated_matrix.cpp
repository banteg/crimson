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

extern float grim_rotation_radians;
extern float grim_rotation_m00;
extern float grim_rotation_m01;
extern float grim_rotation_m10;
extern float grim_rotation_m11;

extern GrimVertex *grim_vertex_write_ptr;
extern GrimDepth grim_vertex_z;
extern unsigned long grim_color_slot0;
extern unsigned long grim_color_slot1;
extern unsigned long grim_color_slot2;
extern unsigned long grim_color_slot3;
extern GrimUV grim_uv_u0[4];
extern unsigned long grim_vertex_count;
extern unsigned int grim_vertex_capacity;

inline void grim_transform_quad_point(float *point)
{
    float transformed_x =
        grim_rotation_m00 * point[0] + grim_rotation_m01 * point[1];
    point[1] = grim_rotation_m10 * point[0] + grim_rotation_m11 * point[1];
    point[0] = transformed_x;
}

void IGrim2D_cpp::grim_draw_quad_rotated_matrix(
    float x, float y, float w, float h)
{
#if CL_BUILD == 10908
    // 1.9.8 stores the rotation centre after the four corners.
    enum { corner = 0, center = 4 };
#else
    enum { center = 0, corner = 1 };
#endif
    float points[5][2];

    if (grim_render_disabled || !grim_device_ready) {
        return;
    }

    if (!grim_batch_active) {
        grim_begin_batch();
    }

    if (grim_rotation_radians == 0.0f) {
        points[corner][0] = x;
        points[corner][1] = y;
        points[corner + 1][0] = x + w;
        points[corner + 1][1] = y;
        points[corner + 2][0] = points[corner + 1][0];
        points[corner + 2][1] = y + h;
        points[corner + 3][0] = x;
        points[corner + 3][1] = points[corner + 2][1];
    } else {
        points[center][0] = x + w * 0.5f;
        points[center][1] = y + h * 0.5f;

        points[corner][0] = w * -0.5f;
        points[corner][1] = h * -0.5f;
        grim_transform_quad_point(points[corner]);
        points[corner][0] += points[center][0];
        points[corner][1] += points[center][1];

        points[corner + 1][0] = w * 0.5f;
        points[corner + 1][1] = h * -0.5f;
        grim_transform_quad_point(points[corner + 1]);
        points[corner + 1][0] += points[center][0];
        points[corner + 1][1] += points[center][1];

        points[corner + 2][0] = w * 0.5f;
        points[corner + 2][1] = h * 0.5f;
        grim_transform_quad_point(points[corner + 2]);
        points[corner + 2][0] += points[center][0];
        points[corner + 2][1] += points[center][1];

        points[corner + 3][0] = w * -0.5f;
        points[corner + 3][1] = h * 0.5f;
        grim_transform_quad_point(points[corner + 3]);
        points[corner + 3][0] += points[center][0];
        points[corner + 3][1] += points[center][1];
    }

    grim_vertex_write_ptr->position = *(GrimPoint *)&points[corner][0];
    grim_vertex_write_ptr->depth = grim_vertex_z;
    grim_vertex_write_ptr->color = grim_color_slot0;
    grim_vertex_write_ptr->uv = grim_uv_u0[0];
    ++grim_vertex_write_ptr;

    grim_vertex_write_ptr->position = *(GrimPoint *)&points[corner + 1][0];
    grim_vertex_write_ptr->depth = grim_vertex_z;
    grim_vertex_write_ptr->color = grim_color_slot1;
    grim_vertex_write_ptr->uv = grim_uv_u0[1];
    ++grim_vertex_write_ptr;

    grim_vertex_write_ptr->position = *(GrimPoint *)&points[corner + 2][0];
    grim_vertex_write_ptr->depth = grim_vertex_z;
    grim_vertex_write_ptr->color = grim_color_slot2;
    grim_vertex_write_ptr->uv = grim_uv_u0[2];
    ++grim_vertex_write_ptr;

    grim_vertex_write_ptr->position = *(GrimPoint *)&points[corner + 3][0];
    grim_vertex_write_ptr->depth = grim_vertex_z;
    grim_vertex_write_ptr->color = grim_color_slot3;
    grim_vertex_write_ptr->uv = grim_uv_u0[3];
    ++grim_vertex_write_ptr;

    *(unsigned short *)&grim_vertex_count += 4;
    if ((unsigned short)grim_vertex_count >= grim_vertex_capacity) {
        grim_flush_batch();
    }
}
