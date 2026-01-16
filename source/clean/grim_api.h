#pragma once

#include <stdbool.h>
#include <stdint.h>

// Provisional Grim2D vtable skeleton.
//
// NOTE: grim.dll methods are called via a vtable pointer at DAT_0048083c.
// The real calling convention is __thiscall on Windows; treat the first
// parameter as the implicit 'this' when calling from C.

typedef struct Grim2D Grim2D;
typedef struct Grim2DVtable Grim2DVtable;

struct Grim2DVtable {
    void (*fn_0x0)(void); // 0x0 (FUN_10005c80)
    void (*fn_0x4)(void); // 0x4 (FUN_10005c90)
    void (*fn_0x8)(void); // 0x8 (FUN_10005ca0)
    void (*fn_0xc)(void); // 0xc (FUN_10005cb0)
    int (*apply_config)(void); // 0x10 (grim_apply_config)
    int (*init_system)(void); // 0x14 (grim_init_system)
    void (*shutdown)(void); // 0x18 (grim_shutdown)
    void (*apply_settings)(void); // 0x1c (grim_apply_settings)
    void (*set_render_state)(uint32_t state, uint32_t value); // 0x20 (FUN_10006580)
    void *(*get_config_var)(void); // 0x24 (grim_get_config_var)
    char *(*get_error_text)(void); // 0x28 (grim_get_error_text)
    void (*clear_color)(float r, float g, float b, float a); // 0x2c (grim_clear_color)
    int (*set_render_target)(int target_index); // 0x30 (grim_set_render_target)
    void (*fn_0x34)(void); // 0x34 (FUN_10006e40)
    void (*fn_0x38)(void); // 0x38 (FUN_10006e50)
    void (*fn_0x3c)(void); // 0x3c (FUN_10006e60)
    void (*fn_0x40)(void); // 0x40 (FUN_10006e90)
    bool (*is_key_down)(uint32_t key); // 0x44 (FUN_10007320)
    bool (*was_key_pressed)(uint32_t key); // 0x48 (FUN_10007390)
    void (*flush_input)(void); // 0x4c (grim_flush_input)
    int (*get_key_char)(void); // 0x50 (FUN_10005c40)
    void (*set_key_char_buffer)(unsigned char *buffer, int *count, int size); // 0x54 (grim_set_key_char_buffer)
    bool (*is_mouse_button_down)(int button); // 0x58 (FUN_10007410)
    void (*fn_0x5c)(void); // 0x5c (FUN_10007440)
    float (*get_mouse_wheel_delta)(void); // 0x60 (FUN_10007560)
    void (*fn_0x64)(void); // 0x64 (FUN_10007530)
    void (*fn_0x68)(void); // 0x68 (FUN_10007510)
    void (*fn_0x6c)(void); // 0x6c (FUN_10007520)
    void (*fn_0x70)(void); // 0x70 (FUN_100074d0)
    void (*fn_0x74)(void); // 0x74 (FUN_100074e0)
    void (*fn_0x78)(void); // 0x78 (FUN_100074f0)
    void (*fn_0x7c)(void); // 0x7c (FUN_10007500)
    bool (*is_key_active)(int key); // 0x80 (FUN_10006fe0)
    float (*get_config_float)(int id); // 0x84 (FUN_100071b0)
    void (*fn_0x88)(void); // 0x88 (FUN_100072c0)
    void (*fn_0x8c)(void); // 0x8c (FUN_100072d0)
    void (*fn_0x90)(void); // 0x90 (FUN_100072e0)
    void (*fn_0x94)(void); // 0x94 (FUN_10007300)
    void (*fn_0x98)(void); // 0x98 (FUN_10007580)
    void (*fn_0x9c)(void); // 0x9c (FUN_10007590)
    void (*fn_0xa0)(void); // 0xa0 (FUN_100075a0)
    void (*fn_0xa4)(void); // 0xa4 (FUN_100075b0)
    void (*fn_0xa8)(void); // 0xa8 (FUN_100075c0)
    bool (*create_texture)(const char *name, int width, int height); // 0xac (FUN_100075d0)
    void (*fn_0xb0)(void); // 0xb0 (FUN_10007790)
    bool (*load_texture)(const char *name, const char *path); // 0xb4 (FUN_100076e0)
    void (*fn_0xb8)(void); // 0xb8 (FUN_10007750)
    void (*fn_0xbc)(void); // 0xbc (FUN_10007700)
    int (*get_texture_handle)(const char *name); // 0xc0 (FUN_10007740)
    void (*bind_texture)(int handle, int stage); // 0xc4 (FUN_10007830)
    void (*fn_0xc8)(void); // 0xc8 (FUN_10007870)
    void (*draw_fullscreen_color)(float r, float g, float b, float a); // 0xcc (grim_draw_fullscreen_color)
    void (*draw_rect_filled)(float *xy, float w, float h); // 0xd0 (grim_draw_rect_filled)
    void (*draw_rect_outline)(float *xy, float w, float h); // 0xd4 (grim_draw_rect_outline)
    void (*draw_circle_filled)(float x, float y, float radius); // 0xd8 (grim_draw_circle_filled)
    void (*draw_circle_outline)(float x, float y, float radius); // 0xdc (grim_draw_circle_outline)
    void (*draw_line)(float *p0, float *p1, float thickness); // 0xe0 (grim_draw_line)
    void (*draw_line_quad)(float *p0, float *p1, float *half_vec); // 0xe4 (grim_draw_line_quad)
    void (*begin_batch)(void); // 0xe8 (grim_begin_batch)
    void (*flush_batch)(void); // 0xec (grim_flush_batch)
    void (*end_batch)(void); // 0xf0 (grim_end_batch)
    void (*fn_0xf4)(void); // 0xf4 (FUN_10008e30)
    void (*fn_0xf8)(void); // 0xf8 (FUN_10008eb0)
    void (*set_rotation)(float radians); // 0xfc (FUN_10007f30)
    void (*set_uv)(float u0, float v0, float u1, float v1); // 0x100 (FUN_10008350)
    void (*set_atlas_frame)(int atlas, int frame); // 0x104 (FUN_10008230)
    void (*set_sub_rect)(int x, int y, int w, int h); // 0x108 (FUN_100082c0)
    void (*set_uv_point)(int index, float u, float v); // 0x10c (grim_set_uv_point)
    void (*set_pivot)(const float *xy); // 0x110 (FUN_10008040)
    void (*set_color)(float r, float g, float b, float a); // 0x114 (FUN_10007f90)
    void (*set_color_slot)(int index, float r, float g, float b, float a); // 0x118 (grim_set_color_slot)
    void (*draw_quad)(float x, float y, float w, float h); // 0x11c (FUN_10008b10)
    void (*draw_quad_xy)(float *xy, float w, float h); // 0x120 (grim_draw_quad_xy)
    void (*fn_0x124)(void); // 0x124 (FUN_10008750)
    void (*submit_vertices_transform)(float *verts, int count, float *offset, float *matrix); // 0x128 (grim_submit_vertices_transform)
    void (*submit_vertices_offset)(float *verts, int count, float *offset); // 0x12c (grim_submit_vertices_offset)
    void (*submit_vertices_offset_color)(float *verts, int count, float *offset, float *color); // 0x130 (grim_submit_vertices_offset_color)
    void (*submit_vertices_transform_color)(float *verts, int count, float *offset, float *matrix, float *color); // 0x134 (grim_submit_vertices_transform_color)
    void (*draw_quad_points)(float x0, float y0, float x1, float y1, float x2, float y2, float x3, float y3); // 0x138 (grim_draw_quad_points)
    void (*draw_text_mono)(float x, float y, const char *text); // 0x13c (FUN_100092b0)
    void (*draw_text_mono_fmt)(float x, float y, const char *fmt, ...); // 0x140 (grim_draw_text_mono_fmt)
    void (*draw_text_small)(float x, float y, const char *text); // 0x144 (FUN_10009730)
    void (*draw_text_box)(float x, float y, const char *text, ...); // 0x148 (FUN_10009980)
    int (*measure_text_width)(const char *text); // 0x14c (FUN_100096c0, small font)
};

struct Grim2D {
    Grim2DVtable *vtbl;
};
