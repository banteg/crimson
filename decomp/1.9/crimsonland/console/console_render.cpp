#include <math.h>

#include "crimsonland_console.h"
#include "grim2d_cpp.h"

extern IGrim2D_cpp *grim_interface_ptr;

struct console_vec2_t {
    float x;
    float y;

    console_vec2_t(float x_value, float y_value)
        : x(x_value), y(y_value) {}

    void set(float x_value, float y_value)
    {
        x = x_value;
        y = y_value;
    }
};

struct console_color_t {
    float r;
    float g;
    float b;
    float a;

    console_color_t(
        float r_value,
        float g_value,
        float b_value,
        float a_value)
        : r(r_value), g(g_value), b(b_value), a(a_value) {}

    void set(
        float r_value,
        float g_value,
        float b_value,
        float a_value)
    {
        r = r_value;
        g = g_value;
        b = b_value;
        a = a_value;
    }
};

extern "C" {
extern float screen_width_f;
extern float game_time_s;
extern int console_input_cursor;
extern console_cvar_entry_t *cv_con_mono_font;
extern char console_caret_string[];
extern char console_prompt_format[];
extern char console_prompt_string[];
extern char console_version_string[];

char *console_input_buffer(void);
}

void console_queue_t::render(void)
{
    if ((float)-height < slide_y) {
        int line_y;
        console_log_node_t *node = log_head;
        int visible_lines =
            log_count > height / 16 - 2
                ? height / 16 - 2
                : log_count;

        float ratio = ((float)height + slide_y) / (float)height;
        if (ratio > 1.0f) {
            ratio = 1.0f;
        } else if (ratio < 0.0f) {
            ratio = 0.0f;
        }

        grim_interface_ptr->grim_set_color(0.6f, 0.6f, 0.6f, ratio);
        grim_interface_ptr->grim_set_rotation(0.0f);

        {
            console_color_t background(
                0.140625f, 0.1875f, 0.2890625f, ratio);
            console_vec2_t position(0.0f, slide_y);
            grim_interface_ptr->grim_draw_rect_filled(
                (float *)&position,
                screen_width_f,
                (float)height,
                (float *)&background);

            grim_interface_ptr->grim_set_color(
                0.1f,
                0.6f,
                1.0f,
                ((float)height + slide_y) / (float)height);
            background.set(
                0.21875f,
                0.265625f,
                0.3671875f,
                ((float)height + slide_y) / (float)height);
            position.set(0.0f, (float)height + slide_y - 4.0f);
            grim_interface_ptr->grim_draw_rect_filled(
                (float *)&position,
                screen_width_f,
                4.0f,
                (float *)&background);
            grim_interface_ptr->grim_end_batch();
        }

        grim_interface_ptr->grim_set_config_var(0x15, 2u);
        grim_interface_ptr->grim_set_config_var(0x18, 0.5f);

        grim_interface_ptr->grim_set_color(
            1.0f,
            1.0f,
            1.0f,
            (((float)height + slide_y) / (float)height) * 0.3f);
        grim_interface_ptr->grim_draw_text_small(
            screen_width_f - 210.0f,
            (float)height + slide_y - 18.0f,
            console_version_string);
        grim_interface_ptr->grim_set_color(
            1.0f,
            1.0f,
            1.0f,
            (((float)height + slide_y) / (float)height) * 0.5f);
        grim_interface_ptr->grim_set_color(
            1.0f,
            1.0f,
            1.0f,
            ((float)height + slide_y) / (float)height);

        if (cv_con_mono_font->value != 0.0f) {
            float input_y = (float)((visible_lines + 1) * 16);
            grim_interface_ptr->grim_draw_text_mono(
                10.0f,
                input_y + slide_y,
                console_prompt_string);
            grim_interface_ptr->grim_draw_text_mono(
                26.0f, input_y + slide_y, console_input_buffer());
        } else {
            grim_interface_ptr->grim_draw_text_small_fmt(
                10.0f,
                (float)((visible_lines + 1) * 16) + slide_y,
                console_prompt_format,
                console_input_buffer());
        }

        grim_interface_ptr->grim_set_color(
            0.6f,
            0.6f,
            0.7f,
            ((float)height + slide_y) / (float)height);

        int skip = scroll_offset;
        while (skip > 0) {
            if (node == 0) {
                break;
            }
            node = node->next;
            --skip;
        }

        if (node != 0) {
            line_y = visible_lines * 16;
            while (node != 0) {
                if (visible_lines < 0) {
                    break;
                }
                if (cv_con_mono_font->value != 0.0f) {
                    grim_interface_ptr->grim_draw_text_mono(
                        10.0f, (float)line_y + slide_y, node->text);
                } else {
                    grim_interface_ptr->grim_draw_text_small(
                        10.0f, (float)line_y + slide_y, node->text);
                }
                node = node->next;
                --visible_lines;
                line_y -= 16;
            }
        }

        visible_lines = log_count;
        if (visible_lines > height / 16 - 2) {
            visible_lines = height / 16 - 2;
        }
        ++visible_lines;

        float pulse = (float)sin(game_time_s * 3.0f);
        float pulse_power = (float)pow((double)pulse, 8.0);
        if (pulse_power < 0.2f) {
            pulse_power = 0.2f;
        }
        float caret_alpha =
            (((float)height + slide_y) / (float)height) * pulse_power;
        if (caret_alpha > 1.0f) {
            caret_alpha = 1.0f;
        } else if (caret_alpha < 0.0f) {
            caret_alpha = 0.0f;
        }
        grim_interface_ptr->grim_set_color(
            1.0f, 1.0f, 1.0f, caret_alpha);

        if (cv_con_mono_font->value != 0.0f) {
            grim_interface_ptr->grim_draw_text_mono(
                (float)(console_input_cursor * 8) + 26.0f,
                (float)(visible_lines * 16) + slide_y + 2.0f,
                console_caret_string);
        } else {
            grim_interface_ptr->grim_draw_text_small(
                (float)grim_interface_ptr->grim_measure_text_width(
                    console_input_buffer()) + 16.0f,
                (float)(visible_lines * 16) + slide_y + 2.0f,
                console_caret_string);
        }

        grim_interface_ptr->grim_set_config_var(0x15, 2u);
    }
}
