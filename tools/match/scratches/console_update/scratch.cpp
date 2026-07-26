#include <math.h>
#include <string.h>

#include "crimsonland_console.h"
#include "grim2d_cpp.h"

extern IGrim2D_cpp *grim_interface_ptr;

extern "C" float frame_dt_copy;
extern "C" float console_open_anim_t;
extern "C" char console_input_buf[1024];
extern "C" int console_input_cursor;
extern "C" unsigned char console_input_ready;

extern "C" int console_input_poll(void);
extern "C" char *console_input_buffer(void);
extern "C" void console_input_clear(void);

inline console_history_entry_t::console_history_entry_t(void)
{
    next = 0;
    line = 0;
}

void console_queue_t::update(void)
{
    if (open) {
        console_open_anim_t -= frame_dt_copy * 3.5f;
        if (console_open_anim_t < 0.0f) {
            console_open_anim_t = 0.0f;
        }
        slide_y =
            (float)sin((1.0f - console_open_anim_t) * 1.57079637f) * height -
            height;

        console_input_poll();

        if ((grim_interface_ptr->grim_is_key_down(0x1d) ||
             grim_interface_ptr->grim_is_key_down(0x9d)) &&
            grim_interface_ptr->grim_was_key_pressed(0xc8)) {
            ++scroll_offset;
        } else if (grim_interface_ptr->grim_was_key_pressed(0xc8)) {
            ++history_index;
            console_history_apply();
        }

        if ((grim_interface_ptr->grim_is_key_down(0x1d) ||
             grim_interface_ptr->grim_is_key_down(0x9d)) &&
            grim_interface_ptr->grim_was_key_pressed(0xd0)) {
            --scroll_offset;
        } else if (grim_interface_ptr->grim_was_key_pressed(0xd0)) {
            --history_index;
            if (history_index < 0) {
                history_index = 0;
            }
            console_history_apply();
        }

        if (grim_interface_ptr->grim_was_key_pressed(0xcb)) {
            --console_input_cursor;
            if (console_input_cursor < 0) {
                console_input_cursor = 0;
            }
        }
        if (grim_interface_ptr->grim_was_key_pressed(0xcd)) {
            ++console_input_cursor;
            if (console_input_cursor > (int)strlen(console_input_buf)) {
                console_input_cursor = strlen(console_input_buf);
            }
        }
        if (grim_interface_ptr->grim_was_key_pressed(0xc9)) {
            scroll_offset += 2;
        }
        if (grim_interface_ptr->grim_was_key_pressed(0xd1)) {
            scroll_offset -= 2;
            if (scroll_offset < 0) {
                scroll_offset = 0;
            }
        }
        if (grim_interface_ptr->grim_was_key_pressed(0xc7)) {
            scroll_offset += 20;
        }
        if (grim_interface_ptr->grim_was_key_pressed(0xcf)) {
            scroll_offset = 0;
        }

        if (grim_interface_ptr->grim_was_key_pressed(0x0f)) {
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
            console_printf(
                &console_log_queue, "> %s\n", console_input_buffer());
            exec_line(console_input_buffer());
            console_input_clear();
            grim_interface_ptr->grim_was_key_pressed(0x1c);
            return;
        }

        console_input_buffer();
        grim_interface_ptr->grim_was_key_pressed(0x1c);
    } else {
        console_open_anim_t += frame_dt_copy * 3.5f;
        if (console_open_anim_t > 1.0f) {
            console_open_anim_t = 1.0f;
        }
        slide_y =
            (float)sin((1.0f - console_open_anim_t) * 1.57079637f) * height -
            height;
    }
}
