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

#include <string.h>

#include "grim_d3d8.h"
#include "grim2d_cpp.h"

extern unsigned char grim_render_disabled;
extern unsigned char grim_font_texture_bound;
extern IDirect3DDevice8 *grim_d3d_device;
extern IDirect3DBaseTexture8 *grim_font_texture;
extern float grim_font_scale;

struct GrimMonoPoint {
    float x;
    float y;

    GrimMonoPoint(float x_value, float y_value) : x(x_value), y(y_value) {}
};

extern GrimMonoPoint grim_font2_uv_u[];

void IGrim2D_cpp::grim_draw_text_mono(float x, float y, char *text)
{
    if (grim_render_disabled || text == 0) {
        return;
    }

    if (!grim_font_texture_bound) {
        grim_d3d_device->SetTexture(0, grim_font_texture);
    }

    float scale = grim_font_scale;
    GrimMonoPoint origin(x, y);
    GrimMonoPoint cursor(origin);

    grim_set_rotation(0.0f);
    grim_begin_batch();

    float cell_size = scale * 32.0f;
    float advance = scale * 16.0f;
    int length = strlen(text);
    bool combine = false;
    GrimMonoPoint uv(0.0f, 0.0f);

    for (int index = 0; index < length; ++index) {
        char character = text[index];
        if (character == '\n') {
            cursor.x = origin.x;
            cursor.y += scale * 28.0f;
        } else if (character == '\xa7') {
            combine = true;
        } else if (character == '\xe5') {
            cursor.x += advance;

            uv = grim_font2_uv_u['a'];
            GrimMonoPoint uv1(uv.x + 0.0625f, uv.y + 0.0625f);
            grim_set_uv(uv.x, uv.y, uv1.x, uv1.y);
            grim_draw_quad(cursor.x, cursor.y + 1.0f, cell_size, cell_size);

            uv = grim_font2_uv_u['.'];
            GrimMonoPoint mark_uv1(uv.x + 0.0625f, uv.y + 0.0625f);
            grim_set_uv(uv.x, uv.y, mark_uv1.x, mark_uv1.y);
            grim_draw_quad(cursor.x, cursor.y - 6.0f, cell_size, cell_size);
        } else if (character == '\xe4') {
            cursor.x += advance;

            uv = grim_font2_uv_u['a'];
            GrimMonoPoint uv1(uv.x + 0.0625f, uv.y + 0.0625f);
            grim_set_uv(uv.x, uv.y, uv1.x, uv1.y);
            grim_draw_quad(cursor.x, cursor.y + 1.0f, cell_size, cell_size);

            uv = grim_font2_uv_u['"'];
            GrimMonoPoint mark_uv1(uv.x + 0.0625f, uv.y + 0.0625f);
            grim_set_uv(uv.x, uv.y, mark_uv1.x, mark_uv1.y);
            grim_draw_quad(cursor.x, cursor.y, cell_size, cell_size);
        } else if (character == '\xf6') {
            cursor.x += advance;

            uv = grim_font2_uv_u['o'];
            GrimMonoPoint uv1(uv.x + 0.0625f, uv.y + 0.0625f);
            grim_set_uv(uv.x, uv.y, uv1.x, uv1.y);
            grim_draw_quad(cursor.x, cursor.y + 1.0f, cell_size, cell_size);

            uv = grim_font2_uv_u['"'];
            GrimMonoPoint mark_uv1(uv.x + 0.0625f, uv.y + 0.0625f);
            grim_set_uv(uv.x, uv.y, mark_uv1.x, mark_uv1.y);
            grim_draw_quad(cursor.x, cursor.y, cell_size, cell_size);
        } else {
            if (combine) {
                combine = false;
            } else {
                cursor.x += advance;
            }

            int glyph = character;
            uv = grim_font2_uv_u[glyph];
            GrimMonoPoint uv1(uv.x + 0.0625f, uv.y + 0.0625f);
            grim_set_uv(uv.x, uv.y, uv1.x, uv1.y);
            grim_draw_quad(cursor.x, cursor.y + 1.0f, cell_size, cell_size);
        }
    }

    grim_end_batch();
}
