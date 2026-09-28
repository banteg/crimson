#include <string.h>

#include "grim2d_cpp.h"

extern unsigned char grim_render_disabled;
extern float *grim_vertex_write_ptr;
extern unsigned long grim_vertex_count;
extern unsigned int grim_vertex_capacity;

void IGrim2D_cpp::grim_submit_quad_raw(float *vertices)
{
    if (grim_render_disabled) {
        return;
    }

    memcpy(grim_vertex_write_ptr, vertices, 0x70);
    grim_vertex_write_ptr += 28;
    *(unsigned short *)&grim_vertex_count += 4;
    if ((unsigned short)grim_vertex_count >= grim_vertex_capacity) {
        grim_flush_batch();
    }
}
