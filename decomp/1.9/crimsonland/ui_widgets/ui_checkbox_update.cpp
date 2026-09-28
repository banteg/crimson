#include "crimsonland_gameplay.h"
#include "crimsonland_ui.h"
#include "grim2d_cpp.h"

extern IGrim2D_cpp *grim_interface_ptr;

struct checkbox_vec2_t {
    float x;
    float y;

    checkbox_vec2_t(float x_value, float y_value)
        : x(x_value), y(y_value) {}
};

extern "C" {
extern unsigned char ui_focus_input_locked;

bool ui_focus_update(int id);
void ui_focus_draw(float *xy);
bool input_primary_just_pressed(void);
}

extern "C" bool ui_checkbox_update(
    float *xy,
    ui_checkbox_t *checkbox)
{
    bool activated = false;
    bool focused = ui_focus_update((int)checkbox);
    char *label = checkbox->label;
    checkbox->hovered = 0;

    if (label) {
        if ((unsigned char)ui_mouse_inside_rect(
                xy,
                16,
                grim_interface_ptr->grim_measure_text_width(label) + 22)) {
            checkbox->hovered = 1;
        }
    } else if ((unsigned char)ui_mouse_inside_rect(xy, 16, 16)) {
        checkbox->hovered = 1;
    }

    if (checkbox->disabled) {
        checkbox->hovered = 0;
    }
    if (checkbox->hovered) {
        ui_focus_set((int)checkbox, 0);
    }

    if (focused) {
        checkbox_vec2_t focus_position(xy[0] - 16.0f, xy[1]);
        ui_focus_draw((float *)&focus_position);
    }

    grim_interface_ptr->grim_set_uv(0.0f, 0.0f, 1.0f, 1.0f);
    if (checkbox->checked) {
        grim_interface_ptr->grim_bind_texture(
            grim_interface_ptr->grim_get_texture_handle("ui_checkOn"), 0);
    } else {
        grim_interface_ptr->grim_bind_texture(
            grim_interface_ptr->grim_get_texture_handle("ui_checkOff"), 0);
    }

    if (!ui_focus_input_locked
        && ((focused && grim_interface_ptr->grim_was_key_pressed(28))
            || (checkbox->hovered && input_primary_just_pressed()))) {
        activated = true;
        checkbox->checked = !checkbox->checked;
    }

    grim_interface_ptr->grim_set_config_var(0x15, 1u);
    grim_interface_ptr->grim_set_color(1.0f, 1.0f, 1.0f, 1.0f);
    grim_interface_ptr->grim_begin_batch();
    grim_interface_ptr->grim_set_rotation(0.0f);
    grim_interface_ptr->grim_draw_quad(xy[0], xy[1], 16.0f, 16.0f);
    grim_interface_ptr->grim_end_batch();
    grim_interface_ptr->grim_set_config_var(0x15, 2u);
    grim_interface_ptr->grim_set_config_var(0x18, 0.5f);

    if (checkbox->hovered) {
        grim_interface_ptr->grim_set_color(1.0f, 1.0f, 1.0f, 1.0f);
    } else {
        grim_interface_ptr->grim_set_color(1.0f, 1.0f, 1.0f, 0.7f);
    }

    label = checkbox->label;
    if (label) {
        grim_interface_ptr->grim_draw_text_small(
            xy[0] + 22.0f, xy[1] + 1.0f, label);
    }

    return activated;
}
