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

extern "C" void ui_element_layout_calc(ui_element_t *element)
{
    if (element == &ui_element_slot_26 || element == &ui_element_slot_27) {
        return;
    }

    ui_layout_vec2_t &position =
        *(ui_layout_vec2_t *)&element->pos;
    ui_layout_vec2_t &hover_min =
        *(ui_layout_vec2_t *)&element->hover_min;
    ui_layout_vec2_t &hover_max =
        *(ui_layout_vec2_t *)&element->hover_max;
    ui_layout_vec2_t &vertex_0 =
        *(ui_layout_vec2_t *)&element->vertices[0].position;
    ui_layout_vec2_t &vertex_2 =
        *(ui_layout_vec2_t *)&element->vertices[2].position;

    hover_min += position + vertex_0;
    hover_max += position + vertex_0;

    hover_min = position + vertex_0;
    float width = vertex_2.x - vertex_0.x;
    hover_min.x += width * 0.54f;
    float height = vertex_2.y - vertex_0.y;
    hover_min.y += height * 0.28f;

    hover_max = position + vertex_2;
    unsigned char direction_flag = element->direction_flag;
    hover_max.x -= width * 0.05f;
    hover_max.y -= height * 0.1f;

    if (direction_flag) {
        for (int i = 0; i < element->vertex_count; i += 2) {
            float u = element->vertices[i].u;
            element->vertices[i].u = element->vertices[i + 1].u;
            element->vertices[i + 1].u = u;
        }
    }
}
