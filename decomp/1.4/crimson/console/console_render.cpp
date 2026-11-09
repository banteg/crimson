#include <math.h>
#include <string.h>

#include "crimsonland_console.h"
#include "grim2d_cpp.h"

extern "C" {
extern IGrim2D_cpp *freeware_console_grim;
extern float frame_dt_copy;
extern float screen_width_f;
extern float freeware_real_clock;
extern console_queue_t freeware_console;
extern char console_input_buf[1024];
extern int console_input_cursor;
extern unsigned char console_input_ready;

int console_input_poll(void);
char *console_input_buffer(void);
void console_input_clear(void);
}

inline console_history_entry_t::console_history_entry_t(void)
{
    next = 0;
    line = 0;
}

void console_queue_t::render(void)
{
    if (open) {
        if (slide_y < 0.0f) {
            slide_y += frame_dt_copy * 500.0f;
        } else {
            slide_y = 0.0f;
        }

        console_input_poll();

        if ((freeware_console_grim->grim_is_key_down(0x1d) ||
             freeware_console_grim->grim_is_key_down(0x9d)) &&
            freeware_console_grim->grim_was_key_pressed(0xc8)) {
            ++scroll_offset;
        } else if (freeware_console_grim->grim_was_key_pressed(0xc8)) {
            ++history_index;
            console_history_apply();
        }

        if ((freeware_console_grim->grim_is_key_down(0x1d) ||
             freeware_console_grim->grim_is_key_down(0x9d)) &&
            freeware_console_grim->grim_was_key_pressed(0xd0)) {
            --scroll_offset;
        } else if (freeware_console_grim->grim_was_key_pressed(0xd0)) {
            --history_index;
            if (history_index < 0) {
                history_index = 0;
            }
            console_history_apply();
        }

        if (freeware_console_grim->grim_was_key_pressed(0xcb)) {
            --console_input_cursor;
            if (console_input_cursor < 0) {
                console_input_cursor = 0;
            }
        }
        if (freeware_console_grim->grim_was_key_pressed(0xcd)) {
            ++console_input_cursor;
            if (console_input_cursor > (int)strlen(console_input_buf)) {
                console_input_cursor = strlen(console_input_buf);
            }
        }
        if (freeware_console_grim->grim_was_key_pressed(0xc9)) {
            scroll_offset += 2;
        }
        if (freeware_console_grim->grim_was_key_pressed(0xd1)) {
            scroll_offset -= 2;
            if (scroll_offset < 0) {
                scroll_offset = 0;
            }
        }
        if (freeware_console_grim->grim_was_key_pressed(0x0f)) {
            console_tokenize_line(console_input_buffer());
            char *completion = console_cvar_autocomplete(console_input_buffer());
            if (completion == 0) {
                completion = console_command_autocomplete(console_input_buffer());
            }
            if (completion != 0) {
                strcpy(console_input_buf, completion);
                console_input_cursor = strlen(completion);
            }
        }

        if (console_input_ready) {
            if (strcmp(history_head->line, console_input_buffer()) != 0) {
                console_history_entry_t *entry = new console_history_entry_t;
                entry->line = strdup_malloc(console_input_buffer());
                entry->next = history_head;
                history_head = entry;
            }
            history_index = 0;
            console_tokenize_line(console_input_buffer());
            console_printf(&freeware_console, "> %s\n", console_input_buffer());
            if (console_cmd_argc != 0) {
                console_cvar_entry_t *cvar = console_cvar_find(console_cmd_name[0]);
                console_command_entry_t *command =
                    console_command_find(console_cmd_name[0]);
                if (cvar != 0) {
                    console_printf(
                        this, "\"%s\" is \"%s\"", cvar->name, cvar->string_value);
                } else if (command != 0) {
                    command->handler();
                } else {
                    console_printf(this, "Unknown command \"%s\"", console_cmd_name[0]);
                }
            }
            console_input_clear();
        } else {
            console_input_buffer();
        }
    } else if (slide_y > (float)-height) {
        slide_y -= frame_dt_copy * 500.0f;
    } else {
        slide_y = (float)-height;
    }

    if ((float)-height < slide_y) {
        int line_y;
        console_log_node_t *node = log_head;
        int visible_lines =
            log_count > height / 16 - 2
                ? height / 16 - 2
                : log_count;

        freeware_console_grim->grim_set_color(0.6f, 0.6f, 0.6f, (height + slide_y) / height);
        freeware_console_grim->grim_bind_texture(
            freeware_console_grim->grim_get_texture_handle("conback"), 0);
        freeware_console_grim->grim_set_rotation(0.0f);
        freeware_console_grim->grim_set_uv(
            0.0f, 0.0f, screen_width_f / 256.0f, height / 256.0f);
        freeware_console_grim->grim_draw_quad(0.0f, slide_y, screen_width_f, (float)height);
        freeware_console_grim->grim_set_uv(
            0.0f, 0.0f, screen_width_f / 256.0f, 10.0f / 256.0f);
        freeware_console_grim->grim_set_color(0.1f, 0.6f, 1.0f, (height + slide_y) / height);
        freeware_console_grim->grim_draw_quad(
            0.0f, height + slide_y - 4.0f, screen_width_f, 4.0f);
        freeware_console_grim->grim_end_batch();
        freeware_console_grim->grim_set_color(1.0f, 1.0f, 1.0f, (height + slide_y) / height);
        freeware_console_grim->grim_set_config_var(0x15, 2u);
        freeware_console_grim->grim_set_config_var(0x18, 0.5f);

        float input_y = (float)((visible_lines + 1) * 16);
        freeware_console_grim->grim_draw_text_mono(10.0f, input_y + slide_y, ">");
        freeware_console_grim->grim_draw_text_mono(
            26.0f, input_y + slide_y, console_input_buffer());
        freeware_console_grim->grim_set_color(0.2f, 0.6f, 0.4f, (height + slide_y) / height);

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
                freeware_console_grim->grim_draw_text_mono(
                    10.0f, (float)line_y + slide_y, node->text);
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

        float pulse = (float)sin(freeware_real_clock * 3.0f);
        float pulse_power = (float)pow((double)pulse, 8.0);
        if (pulse_power < 0.2f) {
            pulse_power = 0.2f;
        }
        freeware_console_grim->grim_set_color(
            1.0f, 1.0f, 1.0f, (height + slide_y) * pulse_power / height);
        freeware_console_grim->grim_draw_text_mono(
            (float)(console_input_cursor * 8) + 26.0f,
            (float)(visible_lines * 16) + slide_y + 2.0f, "_");
        freeware_console_grim->grim_set_config_var(0x15, 2u);
    }
}
