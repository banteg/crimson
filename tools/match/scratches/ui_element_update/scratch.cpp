#include <math.h>

#include "crimsonland_gameplay.h"
#include "crimsonland_ui.h"

struct ui_update_vec2_t {
    float x;
    float y;

    ui_update_vec2_t(float x_value, float y_value)
        : x(x_value), y(y_value) {}
};

static __inline float abs_bits(float value)
{
    unsigned int bits = *(unsigned int *)&value;
    bits &= 0x7fffffff;
    return *(float *)&bits;
}

extern "C" {
extern unsigned char ui_focus_input_locked;
extern ui_element_t *ui_element_hover_focus_ptr;
extern int ui_element_hover_focus_index;
extern int frame_dt_ms;
extern int ui_elements_timeline;
extern int sfx_ui_buttonclick;
extern int sfx_ui_panelclick;

unsigned char input_primary_just_pressed(void);
}

static __inline void ui_element_set_hover_focus(ui_element_t *element)
{
    game_state_id_t state = game_state_id;
    ui_element_hover_focus_ptr = element;
    ui_element_hover_focus_index = 0;

    ui_element_t **cursor = &ui_element_table_end;
    do {
        ui_element_t *candidate = *cursor;
        if (candidate->enabled) {
            if (state != GAME_STATE_MAIN_MENU
                || candidate->on_activate != 0) {
                if (element == candidate) {
                    break;
                }
                ++ui_element_hover_focus_index;
            }
        }
        ++cursor;
    } while ((int)cursor < (int)&ui_perk_prompt_element);
}

static __inline void ui_element_set_rotation(
    ui_element_t *element,
    float radians)
{
    float cosine = (float)cos(radians);
    element->rot_m00 = cosine;
    float sine = (float)sin(radians);
    element->rot_m01 = -sine;
    element->rot_m10 = sine;
    element->rot_m11 = cosine;
}

extern "C" void ui_element_update(ui_element_t *element)
{
    if (element->focus_disabled || !element->active) {
        return;
    }

    if (ui_mouse_x > element->hover_min_x
        && ui_mouse_y > element->hover_min_y
        && ui_mouse_x < element->hover_max_x
        && ui_mouse_y < element->hover_max_y
        && !ui_mouse_blocked
        && !ui_focus_input_locked) {
        unsigned char enabled = element->enabled;
        element->hover_enter_played = 1;

        if (enabled && element->on_activate) {
            ui_element_set_hover_focus(element);
        }
    } else {
        element->hover_enter_played = 0;
    }

    element->time_since_ready += frame_dt_ms;
    unsigned char hovered = element->hover_enter_played;
    if (hovered) {
        element->hover_amount += frame_dt_ms * 6;
    } else {
        element->hover_amount -= frame_dt_ms * 2;
    }

    if (element->hover_amount < 0) {
        element->hover_amount = 0;
    }
    if (element->hover_amount > 1000) {
        element->hover_amount = 1000;
    }

    if (element->on_activate
        && element->time_since_ready >= 255
        && hovered
        && input_primary_just_pressed()) {
        sfx_play(sfx_ui_buttonclick, 1.0f);
        element->on_activate();
    }

    int timeline_end = element->timeline_end_ms;
    int timeline = ui_elements_timeline;
    float angle;
    if (timeline >= timeline_end) {
        if (!element->enabled) {
            sfx_play(sfx_ui_panelclick, 1.0f);
            element->enabled = 1;
        }

        if (element->time_since_ready <= 255) {
            element->time_since_ready += frame_dt_ms;
        }

        angle = 0.0f;
        *(ui_update_vec2_t *)&element->render_offset_x =
            ui_update_vec2_t(0.0f, 0.0f);
    } else {
        int timeline_start = element->timeline_start_ms;
        if (timeline >= timeline_start) {
            int duration = timeline_end - timeline_start;
            int elapsed = timeline - timeline_start;
            angle = 1.57079637f
                - (float)elapsed * 1.57079637f / (float)duration;

            float width =
                element->vertices[0].x - element->vertices[1].x;
            element->render_offset_y = 0.0f;
            if (element->direction_flag) {
                element->render_offset_x = (1.0f
                    - ((float)ui_elements_timeline - (float)timeline_start)
                        / (float)duration) * abs_bits(width);
            } else {
                element->render_offset_x = -((1.0f
                    - ((float)ui_elements_timeline - (float)timeline_start)
                        / (float)duration) * abs_bits(width));
            }
        } else {
            angle = 1.57079637f;
            float width =
                element->vertices[0].x - element->vertices[1].x;
            element->render_offset_y = 0.0f;
            if (element->direction_flag) {
                element->render_offset_x = abs_bits(width);
            } else {
                element->render_offset_x = -abs_bits(width);
            }
        }
    }

    if (ui_get_element_index(element) == 0) {
        angle = -abs_bits(angle);
    }

    if (ui_elements_timeline < element->timeline_end_ms
        && element->enabled) {
        element->enabled = 0;
    }

    ui_element_set_rotation(element, angle);
}
