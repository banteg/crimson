#include <string.h>

#include "grim2d_cpp.h"

extern IGrim2D_cpp *grim_interface_ptr;

extern "C" char *wrap_text_to_width_alloc(char *text, int max_width_px)
{
    int text_length = strlen(text);
    char *wrapped = new char[text_length + 1];
    strcpy(wrapped, text);

    int remaining = max_width_px;
    for (int i = 0; i < text_length; ++i) {
        --remaining;
        if (remaining < 0) {
            remaining = -1;
            if (wrapped[i] == ' ') {
                wrapped[i] = '\n';
                remaining = max_width_px;
            }
        }
    }
    return wrapped;
}
