#include <string.h>

#include "grim2d_cpp.h"

extern unsigned char grim_render_disabled;
extern float *grim_vertex_write_ptr;
extern unsigned long grim_vertex_count;
extern unsigned int grim_vertex_capacity;

inline void grim_rotate_point(float *point, float *matrix)
{
    float x = point[0] * matrix[0] + point[1] * matrix[1];
    point[1] = point[0] * matrix[2] + point[1] * matrix[3];
    point[0] = x;
}

inline void grim_translate_point(float *point, float *offset)
{
    float x = offset[0];
    point[0] += x;
    float y = offset[1];
    point[1] += y;
}

void IGrim2D_cpp::grim_submit_vertices_transform(
    float *vertices, int count, float *offset, float *matrix)
{
    if (grim_render_disabled == 0) {
        memcpy(grim_vertex_write_ptr, vertices, count * 0x1c);
        for (int i = 0; i < count; ++i) {
            grim_rotate_point(grim_vertex_write_ptr, matrix);
            grim_translate_point(grim_vertex_write_ptr, offset);
            grim_vertex_write_ptr += 7;
        }
        *(unsigned short *)&grim_vertex_count += (short)count;
        if ((unsigned short)grim_vertex_count >= grim_vertex_capacity) {
            grim_flush_batch();
        }
    }
}
