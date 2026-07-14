#include <string.h>

#include "grim2d_cpp.h"

extern unsigned char grim_render_disabled;
extern int grim_font2_texture_handle;
extern grim_config_value_t grim_config_values[128];
extern unsigned char grim_font2_char_map[256];
extern unsigned char grim_font2_glyph_widths[256];
extern float grim_font2_uv_u[];
extern float grim_font2_uv_v[];

struct GrimTextPoint {
    float x;
    float y;

    GrimTextPoint(float x_value, float y_value) : x(x_value), y(y_value) {}
};

void IGrim2D_cpp::grim_draw_text_small(float x, float y, char *text)
{
    if (grim_render_disabled || text == 0) {
        return;
    }

    x = (float)(int)x;
    y = (float)(int)y;

    if (grim_font2_texture_handle == -1) {
        grim_font2_texture_handle = grim_get_texture_handle("GRIM_Font2");
        if (grim_font2_texture_handle == -1) {
            return;
        }
    }
    grim_bind_texture(grim_font2_texture_handle, 0);

    GrimTextPoint origin(x, y);
    GrimTextPoint cursor(origin);
    unsigned long saved_filter = grim_config_values[0x15].words[0];
    if (saved_filter != 1) {
        grim_set_config_var(0x15, 1);
    }

    grim_set_rotation(0.0f);
    grim_begin_batch();

    int length = strlen(text);
    for (int index = 0; index < length; ++index) {
        unsigned int glyph = grim_font2_char_map[(unsigned char)text[index]];
        if (text[index] == '\n') {
            cursor.x = origin.x;
            cursor.y += 16.0f;
            continue;
        }

        float width = (float)grim_font2_glyph_widths[glyph];
        GrimTextPoint uv0(
            grim_font2_uv_u[glyph * 2] + 0.001953125f,
            grim_font2_uv_v[glyph * 2] + 0.001953125f
        );
        GrimTextPoint uv1_raw(
            width * 0.00390625f + uv0.x,
            uv0.y + 0.0625f
        );
        GrimTextPoint uv1(
            uv1_raw.x - 0.001953125f,
            uv1_raw.y - 0.001953125f
        );
        grim_set_uv(uv0.x, uv0.y, uv1.x, uv1.y);
        grim_draw_quad(cursor.x, cursor.y, width, 16.0f);
        cursor.x += width;
    }

    grim_end_batch();
    grim_set_config_var(0x15, saved_filter);
}
