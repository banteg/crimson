#include <string.h>

#include "grim2d_cpp.h"

struct GrimDepth {
    float z;
    float rhw;

    GrimDepth() {}
    GrimDepth(float z_value, float rhw_value)
        : z(z_value), rhw(rhw_value) {}
};

struct GrimUV {
    float u;
    float v;

    GrimUV() {}
    GrimUV(float u_value, float v_value) : u(u_value), v(v_value) {}
};

extern grim_config_value_t grim_config_default;
extern grim_config_value_t grim_config_values[128];

extern "C" bool grim_missing_frame_callback(void);
extern "C" bool grim_default_device_callback(void);

extern GrimDepth grim_vertex_z;
extern GrimUV grim_uv_u0[4];

extern float grim_joystick_deadzone;
extern float grim_joystick_center_x;
extern float grim_joystick_center_y;
extern char *grim_error_text;
extern char grim_empty_string;
extern unsigned char grim_reserved_d3ac;
extern unsigned char grim_lookup_blob_loaded;
extern void *grim_lookup_blob;
extern int grim_lookup_blob_size;
extern int grim_backbuffer_width;
extern int grim_backbuffer_height;
extern int grim_texture_format;
extern int grim_preferred_texture_format;
extern void *grim_main_window_hwnd;
extern unsigned int grim_color_slot0;
extern unsigned int grim_color_slot1;
extern unsigned int grim_color_slot2;
extern unsigned int grim_color_slot3;
extern unsigned int grim_mouse_button_latch[2];
extern char *grim_window_title;
extern float grim_key_repeat_timers[256];
extern void (*grim_frame_callback)(void);
extern void (*grim_on_device_restore)(void);
extern void (*grim_on_device_lost)(void);
extern unsigned char grim_font2_glyph_widths[256];
extern GrimUV grim_font2_uv_u[256];
extern GrimUV *grim_subrect_ptr_table[17];
extern unsigned char grim_font2_char_map[256];
extern GrimUV grim_subrect_table_0[4];
extern GrimUV grim_subrect_table_1[16];
extern GrimUV grim_subrect_table_2[64];
extern GrimUV grim_subrect_table[256];

void grim_state_init(void)
{
    int x;
    int y;

    memset(&grim_config_default, 0, sizeof(grim_config_default));
    grim_config_values[0] = grim_config_default;
    memcpy(
        &grim_config_values[1],
        &grim_config_values[0],
        127 * sizeof(grim_config_values[0]));

    grim_config_values[0x2d] = (char *)grim_missing_frame_callback;
    grim_config_values[6] = (char *)grim_default_device_callback;
    grim_config_values[5] = (char *)grim_default_device_callback;
    grim_config_values[7] = "Grim";
    grim_config_values[8] = false;
    grim_config_values[0x2a] = (unsigned int)480;
    grim_config_values[0x29] = (unsigned int)16;
    grim_config_values[0xb] = false;
    grim_config_values[0xc] = false;
    grim_config_values[0xe] = false;
    grim_config_values[0x33] = (unsigned int)1;
    grim_config_values[0xd] = false;
    grim_config_values[0x57] = false;
    grim_config_values[0x58] = true;
    grim_config_values[0x59] = 1.0f;
    grim_config_values[0x17] = false;
    grim_config_values[0x18] = 1.0f;
    grim_config_values[0x64] = true;
    grim_config_values[0x12] = true;
    grim_config_values[0x13] = (unsigned int)5;
    grim_config_values[0x14] = (unsigned int)6;

    grim_vertex_z = GrimDepth(0.5f, 1.0f);

    grim_joystick_deadzone = 100.0f;
    grim_joystick_center_x = 0.0f;
    grim_joystick_center_y = 0.0f;
    grim_error_text = &grim_empty_string;
    grim_reserved_d3ac = 0;
    grim_lookup_blob_loaded = 0;
    grim_lookup_blob = 0;
    grim_lookup_blob_size = 0;
    grim_backbuffer_width = 640;
    grim_backbuffer_height = 480;
    grim_texture_format = 23;
    grim_preferred_texture_format = 0;
    grim_main_window_hwnd = 0;
    grim_color_slot0 = 0xffffffff;
    grim_color_slot3 = 0xffffffff;
    grim_color_slot2 = 0xffffffff;
    grim_color_slot1 = 0xffffffff;
    grim_uv_u0[0] = GrimUV(0.0f, 0.0f);
    grim_uv_u0[1] = GrimUV(1.0f, 0.0f);
    grim_uv_u0[2] = GrimUV(1.0f, 1.0f);
    grim_uv_u0[3] = GrimUV(0.0f, 1.0f);
    memset(
        grim_mouse_button_latch,
        0,
        sizeof(grim_mouse_button_latch));

    char *default_title = "Grim - No Title";
    grim_window_title = new char[strlen(default_title) + 1];
    strcpy(grim_window_title, default_title);

    memset(grim_key_repeat_timers, 0, sizeof(grim_key_repeat_timers));
    grim_frame_callback = (void (*)(void))grim_missing_frame_callback;
    grim_on_device_restore = (void (*)(void))grim_default_device_callback;
    grim_on_device_lost = (void (*)(void))grim_default_device_callback;
    grim_config_values[0x10].words[3] =
        (unsigned int)strdup(&grim_empty_string);

    memset(grim_font2_glyph_widths, 0, sizeof(grim_font2_glyph_widths));
    {
        y = 0;
        float *row_v_cursor = &grim_font2_uv_u[0].v;
        for (; y < 16; ++y) {
            float row_v = (float)y * 0.0625f;
            x = 0;
            float *entry_v = row_v_cursor;
            row_v_cursor += 32;
            for (; x < 16; entry_v += 2, ++x) {
                entry_v[-1] = (float)x * 0.0625f;
                entry_v[0] = row_v;
            }
        }
    }

    memset(grim_subrect_ptr_table, 0, 16 * sizeof(grim_subrect_ptr_table[0]));
    for (x = 0; x < 256; ++x) {
        grim_font2_char_map[x] = (unsigned char)x;
    }
    grim_font2_char_map[0xe4] = 0xe4;
    grim_font2_char_map[0xf6] = 0xf6;
    grim_font2_char_map[0xc4] = 0xc4;
    grim_font2_char_map[0xd6] = 0xd6;
    grim_font2_char_map[0xc5] = 0xc5;
    grim_font2_char_map[0xe5] = 0xe5;

    grim_subrect_ptr_table[2] = grim_subrect_table_0;
    grim_subrect_ptr_table[4] = grim_subrect_table_1;
    grim_subrect_ptr_table[8] = grim_subrect_table_2;
    grim_subrect_ptr_table[16] = grim_subrect_table;

    {
        y = 0;
        float *row_v_cursor = &grim_subrect_table_0[0].v;
        for (; y < 2; ++y) {
            float row_v = (float)y * 0.5f;
            x = 0;
            float *entry_v = row_v_cursor;
            row_v_cursor += 4;
            for (; x < 2; entry_v += 2, ++x) {
                entry_v[-1] = (float)x * 0.5f;
                entry_v[0] = row_v;
            }
        }
    }
    {
        y = 0;
        float *row_v_cursor = &grim_subrect_table_1[0].v;
        for (; y < 4; ++y) {
            float row_v = (float)y * 0.25f;
            x = 0;
            float *entry_v = row_v_cursor;
            row_v_cursor += 8;
            for (; x < 4; entry_v += 2, ++x) {
                entry_v[-1] = (float)x * 0.25f;
                entry_v[0] = row_v;
            }
        }
    }
    {
        y = 0;
        float *row_v_cursor = &grim_subrect_table_2[0].v;
        for (; y < 8; ++y) {
            float row_v = (float)y * 0.125f;
            x = 0;
            float *entry_v = row_v_cursor;
            row_v_cursor += 16;
            for (; x < 8; entry_v += 2, ++x) {
                entry_v[-1] = (float)x * 0.125f;
                entry_v[0] = row_v;
            }
        }
    }
    {
        for (y = 0; y < 16; ++y) {
            float row_v = (float)y * 0.0625f;
            float *entry_v = &grim_subrect_table[y * 16].v;
            for (x = 0; x < 16; entry_v += 2, ++x) {
                entry_v[-1] = (float)x * 0.0625f;
                entry_v[0] = row_v;
            }
        }
    }
}
