#include <string.h>

#include "grim2d_cpp.h"

extern IGrim2D_cpp *grim_interface_ptr;

extern "C" char *wrap_text_to_width_alloc(char *text, int max_width_px)
{
    char glyph[2];
    int text_length = strlen(text);
    glyph[1] = 0;
    char *wrapped = new char[text_length + 1];
    strcpy(wrapped, text);

    int remaining_width = max_width_px;
    for (int i = 0; i < text_length; ++i) {
        glyph[0] = wrapped[i];
        remaining_width -= grim_interface_ptr->grim_measure_text_width(glyph);
        if (remaining_width < 0) {
            do {
                --i;
            } while (wrapped[i] != ' ');
            remaining_width = max_width_px;
            wrapped[i] = '\n';
        }
    }
    return wrapped;
}
