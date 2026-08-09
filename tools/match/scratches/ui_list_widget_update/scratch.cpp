#include "crimsonland_ui.h"
#include "grim2d_cpp.h"

extern IGrim2D_cpp *grim_interface_ptr;

struct list_vec2_t {
    float x;
    float y;

    list_vec2_t() {}
    list_vec2_t(float x_value, float y_value)
        : x(x_value), y(y_value)
    {
    }

    list_vec2_t operator+(const list_vec2_t &other) const
    {
        return list_vec2_t(x + other.x, y + other.y);
    }
};

struct list_color_t {
    float r;
    float g;
    float b;
    float a;

    list_color_t() {}
    list_color_t(
        float r_value,
        float g_value,
        float b_value,
        float a_value)
        : r(r_value), g(g_value), b(b_value), a(a_value)
    {
    }
};

struct list_widget_t {
    unsigned char enabled;
    unsigned char pad0[3];
    int open;
    int selected_index;
    char **items;
    int item_count;
    unsigned char hovered;
    unsigned char pad1[3];
    int active_index;
};

extern "C" {
bool ui_focus_update(int id);
void ui_focus_draw(float *xy);
}

extern "C" int ui_list_widget_update(
    list_vec2_t *xy, list_widget_t *list)
{
    int max_text_width = 0;
    bool focused = ui_focus_update((int)list);
    for (int i = 0; i < list->item_count; ++i) {
        int text_width =
            grim_interface_ptr->grim_measure_text_width(list->items[i]);
        if (text_width > max_text_width) {
            max_text_width = text_width;
        }
    }

    float width;
    float height;
    if (!list->enabled) {
        height = 16.0f;
        list->hovered = 0;
        width = (float)(max_text_width + 48);
        list->open = 0;
    } else if (list->open > 0) {
        width = (float)(max_text_width + 48);
        height = (float)(list->item_count * 16 + 24);
        list->hovered =
            ui_mouse_inside_rect(
                (float *)xy, (int)height, (int)width);
    } else {
        height = 16.0f;
        list->hovered = 0;
        width = (float)(max_text_width + 48);
    }

    if (list->hovered) {
        ui_focus_set((int)list, 0);
    }

    if (focused) {
        list_vec2_t focus_position(xy->x - 16.0f, xy->y);
        ui_focus_draw((float *)&focus_position);

        if (grim_interface_ptr->grim_was_key_pressed(200)) {
            if (!list->open) {
                list->open = 1;
            } else {
                --list->active_index;
                if (list->active_index < 0) {
                    list->active_index = 0;
                }
            }
        }
        if (grim_interface_ptr->grim_was_key_pressed(208)) {
            if (!list->open) {
                list->open = 1;
            } else {
                ++list->active_index;
                if (list->active_index > list->item_count - 1) {
                    list->active_index = list->item_count - 1;
                }
            }
        }
    }

    {
        list_color_t color(1.0f, 1.0f, 1.0f, 1.0f);
        grim_interface_ptr->grim_draw_rect_filled(
            (float *)xy, width, height, (float *)&color);
    }
    {
        list_vec2_t position(xy->x + 1.0f, xy->y + 1.0f);
        list_color_t color(0.0f, 0.0f, 0.0f, 1.0f);
        grim_interface_ptr->grim_draw_rect_filled(
            (float *)&position,
            width - 2.0f,
            height - 2.0f,
            (float *)&color);
    }

    if (list->open > 0 || list->hovered) {
        list_vec2_t divider_position(xy->x, xy->y + 15.0f);
        list_color_t color(1.0f, 1.0f, 1.0f, 0.5f);
        grim_interface_ptr->grim_draw_rect_filled(
            (float *)&divider_position, width, 1.0f, (float *)&color);
        grim_interface_ptr->grim_bind_texture(
            grim_interface_ptr->grim_get_texture_handle("ui_dropOn"), 0);
    } else {
        grim_interface_ptr->grim_bind_texture(
            grim_interface_ptr->grim_get_texture_handle("ui_dropOff"), 0);
    }

    grim_interface_ptr->grim_set_config_var(0x15, 1u);
    grim_interface_ptr->grim_set_color(1.0f, 1.0f, 1.0f, 1.0f);
    grim_interface_ptr->grim_set_uv(0.0f, 0.0f, 1.0f, 1.0f);
    grim_interface_ptr->grim_begin_batch();
    grim_interface_ptr->grim_draw_quad(
        xy->x + width - 16.0f - 1.0f, xy->y, 16.0f, 16.0f);
    grim_interface_ptr->grim_end_batch();
    grim_interface_ptr->grim_set_config_var(0x15, 2u);

    int result = -2;
    if (list->enabled
        && (unsigned char)ui_mouse_inside_rect_with_padding(
            (float *)xy, 14, (int)width)) {
        result = -1;
        grim_interface_ptr->grim_set_color(1.0f, 1.0f, 1.0f, 0.95f);
    } else {
        grim_interface_ptr->grim_set_color(1.0f, 1.0f, 1.0f, 0.75f);
    }
    grim_interface_ptr->grim_draw_text_small_fmt(
        xy->x + 4.0f,
        xy->y + 1.0f,
        "%s",
        list->items[list->selected_index]);

    if (list->open <= 0) {
        return result;
    }

    grim_interface_ptr->grim_set_color(1.0f, 1.0f, 1.0f, 0.7f);
    for (int row_index = 0;
         row_index < list->item_count;
         ++row_index) {
        list_vec2_t row_position =
            *xy + list_vec2_t(
                0.0f, (float)(row_index * 16 + 16));
        if ((unsigned char)ui_mouse_inside_rect_with_padding(
                (float *)&row_position, 14, (int)width)) {
            list->active_index = row_index;
            grim_interface_ptr->grim_set_color(
                1.0f, 1.0f, 1.0f, 0.95f);
        } else {
            grim_interface_ptr->grim_set_color(
                1.0f, 1.0f, 1.0f, 0.6f);
        }
        if (focused && list->active_index == row_index) {
            grim_interface_ptr->grim_set_color(
                1.0f, 1.0f, 1.0f, 0.96f);
        }
        grim_interface_ptr->grim_draw_text_small_fmt(
            xy->x + 4.0f,
            xy->y + (float)(row_index * 16) + 17.0f,
            "%s",
            list->items[row_index]);
    }

    if (!list->hovered && !focused) {
        list->open = 0;
    }
    return list->active_index;
}
