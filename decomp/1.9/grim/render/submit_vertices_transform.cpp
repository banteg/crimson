#include <string.h>

#include "grim2d_cpp.h"

extern unsigned char grim_render_disabled;
extern float *grim_vertex_write_ptr;
extern unsigned long grim_vertex_count;
extern unsigned int grim_vertex_capacity;

#if CL_BUILD == 10908
// Code-generation guard: 1.9.8 loads the second rotation product and the x
// translation with their operands the other way round. 8966 and 9044 emit
// the same code for every shared spelling; only the inline-copy ids differ,
// with the matrix parameter first and the offsets added directly. See
// NOTES.md.
inline void grim_rotate_point(float *matrix, float *point)
#else
inline void grim_rotate_point(float *point, float *matrix)
#endif
{
    float x = point[0] * matrix[0] + point[1] * matrix[1];
    point[1] = point[0] * matrix[2] + point[1] * matrix[3];
    point[0] = x;
}

inline void grim_translate_point(float *point, float *offset)
{
#if CL_BUILD == 10908
    point[0] += offset[0];
    point[1] += offset[1];
#else
    float x = offset[0];
    point[0] += x;
    float y = offset[1];
    point[1] += y;
#endif
}

void IGrim2D_cpp::grim_submit_vertices_transform(
    float *vertices, int count, float *offset, float *matrix)
{
    if (grim_render_disabled == 0) {
        memcpy(grim_vertex_write_ptr, vertices, count * 0x1c);
        for (int i = 0; i < count; ++i) {
#if CL_BUILD == 10908
            grim_rotate_point(matrix, grim_vertex_write_ptr);
#else
            grim_rotate_point(grim_vertex_write_ptr, matrix);
#endif
            grim_translate_point(grim_vertex_write_ptr, offset);
            grim_vertex_write_ptr += 7;
        }
        *(unsigned short *)&grim_vertex_count += (short)count;
        if ((unsigned short)grim_vertex_count >= grim_vertex_capacity) {
            grim_flush_batch();
        }
    }
}
