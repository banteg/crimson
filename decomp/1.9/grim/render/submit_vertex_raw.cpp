#include <string.h>

#include "grim2d_cpp.h"

extern unsigned char grim_render_disabled;
extern unsigned char grim_device_ready;
extern unsigned char grim_batch_active;
extern float *grim_vertex_write_ptr;
#if CL_BUILD < 10900
extern unsigned short grim_vertex_count;
#else
extern unsigned long grim_vertex_count;
#endif
extern unsigned int grim_vertex_capacity;

void IGrim2D_cpp::grim_submit_vertex_raw(float *vertex)
{
    if (grim_render_disabled || !grim_device_ready) {
        return;
    }

    if (!grim_batch_active) {
        grim_begin_batch();
    }

    memcpy(grim_vertex_write_ptr, vertex, 0x1c);
    grim_vertex_write_ptr += 7;
#if CL_BUILD < 10900
    ++grim_vertex_count;
    if (grim_vertex_count >= grim_vertex_capacity) {
        grim_flush_batch();
    }
#else
    ++*(unsigned short *)&grim_vertex_count;
    if ((unsigned short)grim_vertex_count >= grim_vertex_capacity) {
        grim_flush_batch();
    }
#endif
}
