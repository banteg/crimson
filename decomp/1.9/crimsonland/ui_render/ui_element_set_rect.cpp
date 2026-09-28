#include "crimsonland_audio.h"

struct ui_vec2_t {
    float x;
    float y;

    ui_vec2_t(float x_value, float y_value)
        : x(x_value), y(y_value) {}

    ui_vec2_t &operator+=(const ui_vec2_t &other)
    {
        float result_x = x + other.x;
        x = result_x;
        y += other.y;
        return *this;
    }
};

struct ui_vertex_t {
    ui_vec2_t position;
    struct ui_depth_t {
        float z;
        float rhw;
    } depth;
    unsigned int color;
    ui_vec2_t uv;
};

struct ui_quad_t {
    ui_vertex_t vertices[8];
    int texture_handle;
    int quad_mode;
};

extern "C" void ui_element_set_rect(
    ui_menu_item_subtemplate_block_t *element,
    float width,
    float height,
    float *offset)
{
    ui_quad_t *quad = (ui_quad_t *)element;
    ui_vertex_t *vertices = quad->vertices;
    ui_vertex_t::ui_depth_t depth;
    float inv_width = 1.0f / width;
    float inv_height = 1.0f / height;
    float right = width - 1.0f;

    vertices[0].position = ui_vec2_t(1.0f, 1.0f);
    vertices[1].position = ui_vec2_t(right, 1.0f);

    float bottom = height - 1.0f;
    vertices[3].position = ui_vec2_t(1.0f, bottom);
    vertices[2].position = ui_vec2_t(right, bottom);

    vertices[0].uv = ui_vec2_t(inv_width, inv_height);
    vertices[1].uv = ui_vec2_t(1.0f - inv_width, inv_height);
    vertices[3].uv = ui_vec2_t(inv_width, 1.0f - inv_width);
    vertices[2].uv = ui_vec2_t(1.0f - inv_width, 1.0f - inv_height);

    depth.z = 0.5f;
    depth.rhw = 1.0f;
    for (int i = 0; i < 4; ++i) {
        vertices[i].color = 0xffffffff;
        vertices[i].depth = depth;
        vertices[i].position += *(ui_vec2_t *)offset;
    }
}
