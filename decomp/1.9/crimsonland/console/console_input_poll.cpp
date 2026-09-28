#include "crimsonland_console.h"
#include "grim2d_cpp.h"

extern IGrim2D_cpp *grim_interface_ptr;

extern "C" char console_input_buf[1024];
extern "C" int console_input_cursor;
extern "C" unsigned char console_input_ready;

extern "C" int console_input_poll(void)
{
    int key = grim_interface_ptr->grim_get_key_char();

    if (!console_input_enabled) {
        return key;
    }
    if (!key || console_input_ready) {
        return 0;
    }

    if (key == 13) {
        console_input_ready = 1;
        console_input_buf[console_input_cursor++] = 0;
        return 0;
    }
    if (key == 8) {
        if (console_input_cursor > 0) {
            --console_input_cursor;
        }
        console_input_buf[console_input_cursor] = 0;
        return 0;
    }

    console_input_buf[console_input_cursor++] = (char)key;
    if (console_input_cursor >= 1024) {
        --console_input_cursor;
    }
    console_input_buf[console_input_cursor] = 0;
    return 0;
}
