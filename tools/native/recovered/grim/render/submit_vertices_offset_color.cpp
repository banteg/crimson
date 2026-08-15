#include <string.h>

#include "grim2d_cpp.h"

extern unsigned char grim_render_disabled;
extern unsigned long *grim_vertex_write_ptr;
extern unsigned long grim_vertex_count;
extern unsigned int grim_vertex_capacity;

void IGrim2D_cpp::grim_submit_vertices_offset_color(
    float *vertices,
    int count,
    float *offset,
    unsigned long *color)
{
    if (grim_render_disabled) {
        return;
    }

    memcpy(grim_vertex_write_ptr, vertices, count * 0x1c);

    for (int remaining = count; remaining > 0; --remaining) {
        float *out = (float *)grim_vertex_write_ptr;
        float x = offset[0];
        out[0] = x + out[0];
        float y = offset[1];
        out[1] = y + out[1];
        grim_vertex_write_ptr[4] = *color;
        grim_vertex_write_ptr += 7;
    }

    *(unsigned short *)&grim_vertex_count += (unsigned short)count;
    if ((unsigned short)grim_vertex_count >= grim_vertex_capacity) {
        grim_flush_batch();
    }
}
