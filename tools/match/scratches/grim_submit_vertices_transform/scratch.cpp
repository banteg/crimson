#include <string.h>

#include "grim2d_cpp.h"

extern unsigned char grim_render_disabled;
extern float *grim_vertex_write_ptr;
extern unsigned long grim_vertex_count;
extern unsigned int grim_vertex_capacity;

void IGrim2D_cpp::grim_submit_vertices_transform(
    float *vertices, int count, float *offset, float *matrix)
{
    if (grim_render_disabled == 0) {
        memcpy(grim_vertex_write_ptr, vertices, count * 0x1c);
        if (count > 0) {
            for (int remaining = count; remaining != 0; --remaining) {
                float *out = grim_vertex_write_ptr;
                double rotated_x = out[1];
                rotated_x *= matrix[1];
                double x_term = *matrix;
                x_term *= out[0];
                rotated_x += x_term;
                double rotated_y = out[1];
                rotated_y *= matrix[3];
                double y_term = out[0];
                y_term *= matrix[2];
                rotated_y += y_term;
                out[1] = (float)rotated_y;
                *out = (float)rotated_x;
                float *translated = grim_vertex_write_ptr;
                *grim_vertex_write_ptr = *offset + *grim_vertex_write_ptr;
                float y_offset = offset[1];
                translated[1] = y_offset + translated[1];
                grim_vertex_write_ptr += 7;
            }
        }
        *(unsigned short *)&grim_vertex_count += (short)count;
        if ((unsigned short)grim_vertex_count >= grim_vertex_capacity) {
            grim_flush_batch();
        }
    }
}
