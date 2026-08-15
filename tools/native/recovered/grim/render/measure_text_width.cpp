#include <string.h>

#include "grim2d_cpp.h"

extern unsigned char grim_font2_char_map[256];
extern unsigned char grim_font2_glyph_widths[256];

int IGrim2D_cpp::grim_measure_text_width(char *text)
{
    if (text == 0) {
        return 0;
    }

    int length = strlen(text);
    int maximum = 0;
    int line_width = 0;
    for (int index = 0; index < length; ++index) {
        if (text[index] == '\n') {
            if (line_width > maximum) {
                maximum = line_width;
            }
            line_width = 0;
        } else {
            line_width += grim_font2_glyph_widths[
                grim_font2_char_map[(unsigned char)text[index]]];
        }
    }

    if (line_width > maximum) {
        maximum = line_width;
    }
    return maximum;
}
