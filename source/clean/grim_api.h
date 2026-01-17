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
    void (*release)(void); // 0x0 (grim_release)
    void (*set_paused)(int paused); // 0x4 (grim_set_paused)
    float (*get_version)(void); // 0x8 (grim_get_version)
    int (*check_device)(void); // 0xc (grim_check_device)
    int (*apply_config)(void); // 0x10 (grim_apply_config)
    int (*init_system)(void); // 0x14 (grim_init_system)
    void (*shutdown)(void); // 0x18 (grim_shutdown)
    void (*apply_settings)(void); // 0x1c (grim_apply_settings)
    void (*set_render_state)(uint32_t state, uint32_t value); // 0x20 (FUN_10006580)
    void (*get_config_var)(uint32_t *out, int id); // 0x24 (grim_get_config_var)
    char *(*get_error_text)(void); // 0x28 (grim_get_error_text)
    void (*clear_color)(float r, float g, float b, float a); // 0x2c (grim_clear_color)
    int (*set_render_target)(int target_index); // 0x30 (grim_set_render_target)
    int (*get_time_ms)(void); // 0x34 (grim_get_time_ms)
    void (*set_time_ms)(int ms); // 0x38 (grim_set_time_ms)
    float (*get_frame_dt)(void); // 0x3c (grim_get_frame_dt)
    float (*get_fps)(void); // 0x40 (grim_get_fps)
    bool (*is_key_down)(uint32_t key); // 0x44 (FUN_10007320)
    bool (*was_key_pressed)(uint32_t key); // 0x48 (FUN_10007390)
    void (*flush_input)(void); // 0x4c (grim_flush_input)
    int (*get_key_char)(void); // 0x50 (FUN_10005c40)
    void (*set_key_char_buffer)(unsigned char *buffer, int *count, int size); // 0x54 (grim_set_key_char_buffer)
    bool (*is_mouse_button_down)(int button); // 0x58 (FUN_10007410)
    bool (*was_mouse_button_pressed)(int button); // 0x5c (grim_was_mouse_button_pressed)
    float (*get_mouse_wheel_delta)(void); // 0x60 (FUN_10007560)
    void (*set_mouse_pos)(float x, float y); // 0x64 (grim_set_mouse_pos)
    float (*get_mouse_x)(void); // 0x68 (grim_get_mouse_x)
    float (*get_mouse_y)(void); // 0x6c (grim_get_mouse_y)
    float (*get_mouse_dx)(void); // 0x70 (grim_get_mouse_dx)
    float (*get_mouse_dy)(void); // 0x74 (grim_get_mouse_dy)
    float (*get_mouse_dx_indexed)(int index); // 0x78 (grim_get_mouse_dx_indexed)
    float (*get_mouse_dy_indexed)(int index); // 0x7c (grim_get_mouse_dy_indexed)
    bool (*is_key_active)(int key); // 0x80 (FUN_10006fe0)
    float (*get_config_float)(int id); // 0x84 (FUN_100071b0)
    float (*get_slot_float)(int index); // 0x88 (grim_get_slot_float)
    int (*get_slot_int)(int index); // 0x8c (grim_get_slot_int)
    void (*set_slot_float)(int index, float value); // 0x90 (grim_set_slot_float)
    void (*set_slot_int)(int index, int value); // 0x94 (grim_set_slot_int)
    int (*get_joystick_x)(void); // 0x98 (grim_get_joystick_x)
    int (*get_joystick_y)(void); // 0x9c (grim_get_joystick_y)
    int (*get_joystick_z)(void); // 0xa0 (grim_get_joystick_z)
    int (*get_joystick_pov)(int index); // 0xa4 (grim_get_joystick_pov)
    bool (*is_joystick_button_down)(int button); // 0xa8 (grim_is_joystick_button_down)
    bool (*create_texture)(const char *name, int width, int height); // 0xac (FUN_100075d0)
    bool (*recreate_texture)(int handle); // 0xb0 (grim_recreate_texture)
    bool (*load_texture)(const char *name, const char *path); // 0xb4 (FUN_100076e0)
    bool (*validate_texture)(int handle); // 0xb8 (grim_validate_texture)
    void (*destroy_texture)(int handle); // 0xbc (grim_destroy_texture)
    int (*get_texture_handle)(const char *name); // 0xc0 (FUN_10007740)
    void (*bind_texture)(int handle, int stage); // 0xc4 (FUN_10007830)
    void (*draw_fullscreen_quad)(void); // 0xc8 (grim_draw_fullscreen_quad)
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
    void (*submit_vertex_raw)(const float *vertex); // 0xf4 (grim_submit_vertex_raw)
    void (*submit_quad_raw)(const float *verts); // 0xf8 (grim_submit_quad_raw)
    void (*set_rotation)(float radians); // 0xfc (FUN_10007f30)
    void (*set_uv)(float u0, float v0, float u1, float v1); // 0x100 (FUN_10008350)
    void (*set_atlas_frame)(int atlas_size, int frame); // 0x104 (FUN_10008230)
    void (*set_sub_rect)(int atlas_size, int width, int height, int frame); // 0x108 (FUN_100082c0) atlas_size indexes UV table (2/4/8/16)
    void (*set_uv_point)(int index, float u, float v); // 0x10c (grim_set_uv_point) index 0..3
    void (*set_color_ptr)(float *rgba); // 0x110 (grim_set_color_ptr)
    void (*set_color)(float r, float g, float b, float a); // 0x114 (FUN_10007f90)
    void (*set_color_slot)(int index, float r, float g, float b, float a); // 0x118 (grim_set_color_slot)
    void (*draw_quad)(float x, float y, float w, float h); // 0x11c (FUN_10008b10)
    void (*draw_quad_xy)(float *xy, float w, float h); // 0x120 (grim_draw_quad_xy)
    void (*draw_quad_rotated_matrix)(float x, float y, float w, float h); // 0x124 (grim_draw_quad_rotated_matrix)
    void (*submit_vertices_transform)(float *verts, int count, float *offset, float *matrix); // 0x128 (grim_submit_vertices_transform) verts are 7-float stride
    void (*submit_vertices_offset)(float *verts, int count, float *offset); // 0x12c (grim_submit_vertices_offset) verts are 7-float stride
    void (*submit_vertices_offset_color)(float *verts, int count, float *offset, float *color); // 0x130 (grim_submit_vertices_offset_color) *color is packed ARGB
    void (*submit_vertices_transform_color)(float *verts, int count, float *offset, float *matrix, float *color); // 0x134 (grim_submit_vertices_transform_color) *color is packed ARGB
    void (*draw_quad_points)(float x0, float y0, float x1, float y1, float x2, float y2, float x3, float y3); // 0x138 (grim_draw_quad_points)
    void (*draw_text_mono)(float x, float y, const char *text); // 0x13c (FUN_100092b0)
    void (*draw_text_mono_fmt)(float x, float y, const char *fmt, ...); // 0x140 (grim_draw_text_mono_fmt)
    void (*draw_text_small)(float x, float y, const char *text); // 0x144 (FUN_10009730)
    void (*draw_text_small_fmt)(float x, float y, const char *fmt, ...); // 0x148 (FUN_10009980)
    int (*measure_text_width)(const char *text); // 0x14c (FUN_100096c0, small font)
};

struct Grim2D {
    Grim2DVtable *vtbl;
};
