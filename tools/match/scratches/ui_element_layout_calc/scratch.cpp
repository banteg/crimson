#include "crimsonland_audio.h"
#include "crimsonland_ui.h"

struct ui_layout_vec2_t {
    float x;
    float y;

    ui_layout_vec2_t(float x_value, float y_value)
        : x(x_value), y(y_value) {}

    ui_layout_vec2_t operator+(const ui_layout_vec2_t &other) const
    {
        return ui_layout_vec2_t(other.x + x, other.y + y);
    }

    ui_layout_vec2_t &operator+=(const ui_layout_vec2_t &other)
    {
        x += other.x;
        y += other.y;
        return *this;
    }
};

struct ui_layout_vertex_t {
    ui_layout_vec2_t position;
    float z;
    float rhw;
    unsigned int color;
    ui_layout_vec2_t uv;
};

struct ui_element_layout_t {
    unsigned char _head[0x18];
    ui_layout_vec2_t position;
    ui_layout_vec2_t hover_min;
    ui_layout_vec2_t hover_max;
    unsigned char _pad30[0x0c];
    ui_layout_vertex_t vertices[8];
    int texture_handle;
    int vertex_count;
    unsigned char _pad124[0x1f0];
    unsigned char direction_flag;
};

extern "C" void ui_element_layout_calc(ui_element_t *element)
{
    if (element == &ui_element_slot_26 || element == &ui_element_slot_27) {
        return;
    }

    ui_element_layout_t *layout = (ui_element_layout_t *)element;
    layout->hover_min += layout->position + layout->vertices[0].position;
    layout->hover_max += layout->position + layout->vertices[0].position;

    layout->hover_min = layout->position + layout->vertices[0].position;
    float width = layout->vertices[2].position.x
        - layout->vertices[0].position.x;
    layout->hover_min.x += width * 0.54f;
    float height = layout->vertices[2].position.y
        - layout->vertices[0].position.y;
    layout->hover_min.y += height * 0.28f;

    layout->hover_max = layout->position + layout->vertices[2].position;
    layout->hover_max.x -= width * 0.05f;
    layout->hover_max.y -= height * 0.1f;

    if (layout->direction_flag) {
        for (int i = 0; i < layout->vertex_count; i += 2) {
            float u = layout->vertices[i].uv.x;
            layout->vertices[i].uv.x = layout->vertices[i + 1].uv.x;
            layout->vertices[i + 1].uv.x = u;
        }
    }
}
