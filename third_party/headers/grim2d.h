/* Auto-generated from analysis/ghidra/derived/grim2d_vtable_map.json. */
#ifndef GRIM2D_H
#define GRIM2D_H

typedef struct IGrim2D_vtbl IGrim2D_vtbl;
typedef struct IGrim2D IGrim2D;

struct IGrim2D {
    IGrim2D_vtbl *vtable;
};

struct IGrim2D_vtbl {
    /* 0x000 */ void (__stdcall *grim_release)(void);
    /* 0x004 */ void (__stdcall *grim_set_paused)(int paused);
    /* 0x008 */ float (__stdcall *grim_get_version)(void);
    /* 0x00c */ int (__stdcall *grim_check_device)(void);
    /* 0x010 */ int (__stdcall *grim_apply_config)(void);
    /* 0x014 */ int (__stdcall *grim_init_system)(void);
    /* 0x018 */ void (__stdcall *grim_shutdown)(void);
    /* 0x01c */ void (__stdcall *grim_apply_settings)(void);
    /* 0x020 */ void (*grim_set_config_var)(unsigned int id, unsigned int value, ...);
    /* 0x024 */ void (__stdcall *grim_get_config_var)(unsigned int * out, int id);
    /* 0x028 */ char * (__stdcall *grim_get_error_text)(void);
    /* 0x02c */ void (__stdcall *grim_clear_color)(float r, float g, float b, float a);
    /* 0x030 */ int (__stdcall *grim_set_render_target)(int target_index);
    /* 0x034 */ int (__stdcall *grim_get_time_ms)(void);
    /* 0x038 */ void (__stdcall *grim_set_time_ms)(int ms);
    /* 0x03c */ float (__stdcall *grim_get_frame_dt)(void);
    /* 0x040 */ float (__stdcall *grim_get_fps)(void);
    /* 0x044 */ int (__stdcall *grim_is_key_down)(unsigned int key);
    /* 0x048 */ int (__stdcall *grim_was_key_pressed)(unsigned int key);
    /* 0x04c */ void (__stdcall *grim_flush_input)(void);
    /* 0x050 */ int (__stdcall *grim_get_key_char)(void);
    /* 0x054 */ void (__stdcall *grim_set_key_char_buffer)(unsigned char * buffer, int * count, int size);
    /* 0x058 */ int (__stdcall *grim_is_mouse_button_down)(int button);
    /* 0x05c */ int (__stdcall *grim_was_mouse_button_pressed)(int button);
    /* 0x060 */ float (__stdcall *grim_get_mouse_wheel_delta)(void);
    /* 0x064 */ void (__stdcall *grim_set_mouse_pos)(float x, float y);
    /* 0x068 */ float (__stdcall *grim_get_mouse_x)(void);
    /* 0x06c */ float (__stdcall *grim_get_mouse_y)(void);
    /* 0x070 */ float (__stdcall *grim_get_mouse_dx)(void);
    /* 0x074 */ float (__stdcall *grim_get_mouse_dy)(void);
    /* 0x078 */ float (__stdcall *grim_get_mouse_dx_indexed)(int index);
    /* 0x07c */ float (__stdcall *grim_get_mouse_dy_indexed)(int index);
    /* 0x080 */ int (__stdcall *grim_is_key_active)(int key);
    /* 0x084 */ float (__stdcall *grim_get_config_float)(int id);
    /* 0x088 */ float (__stdcall *grim_get_slot_float)(int index);
    /* 0x08c */ int (__stdcall *grim_get_slot_int)(int index);
    /* 0x090 */ void (__stdcall *grim_set_slot_float)(int index, float value);
    /* 0x094 */ void (__stdcall *grim_set_slot_int)(int index, int value);
    /* 0x098 */ int (__stdcall *grim_get_joystick_x)(void);
    /* 0x09c */ int (__stdcall *grim_get_joystick_y)(void);
    /* 0x0a0 */ int (__stdcall *grim_get_joystick_z)(void);
    /* 0x0a4 */ int (__stdcall *grim_get_joystick_pov)(int index);
    /* 0x0a8 */ int (__stdcall *grim_is_joystick_button_down)(int button);
    /* 0x0ac */ int (__stdcall *grim_create_texture)(char * name, int width, int height);
    /* 0x0b0 */ int (__stdcall *grim_recreate_texture)(int handle);
    /* 0x0b4 */ int (__stdcall *grim_load_texture)(char * name, char * path);
    /* 0x0b8 */ int (__stdcall *grim_validate_texture)(int handle);
    /* 0x0bc */ void (__stdcall *grim_destroy_texture)(int handle);
    /* 0x0c0 */ int (__stdcall *grim_get_texture_handle)(char * name);
    /* 0x0c4 */ void (__stdcall *grim_bind_texture)(int handle, int stage);
    /* 0x0c8 */ void (__stdcall *grim_draw_fullscreen_quad)(void);
    /* 0x0cc */ void (__stdcall *grim_draw_fullscreen_color)(float r, float g, float b, float a);
    /* 0x0d0 */ void (__stdcall *grim_draw_rect_filled)(float * xy, float w, float h);
    /* 0x0d4 */ void (__stdcall *grim_draw_rect_outline)(float * xy, float w, float h);
    /* 0x0d8 */ void (__stdcall *grim_draw_circle_filled)(float x, float y, float radius);
    /* 0x0dc */ void (__stdcall *grim_draw_circle_outline)(float x, float y, float radius);
    /* 0x0e0 */ void (__stdcall *grim_draw_line)(float * p0, float * p1, float thickness);
    /* 0x0e4 */ void (__stdcall *grim_draw_line_quad)(float * p0, float * p1, float * half_vec);
    /* 0x0e8 */ void (__stdcall *grim_begin_batch)(void);
    /* 0x0ec */ void (__stdcall *grim_flush_batch)(void);
    /* 0x0f0 */ void (__stdcall *grim_end_batch)(void);
    /* 0x0f4 */ void (__stdcall *grim_submit_vertex_raw)(float * vertex);
    /* 0x0f8 */ void (__stdcall *grim_submit_quad_raw)(float * verts);
    /* 0x0fc */ void (__stdcall *grim_set_rotation)(float radians);
    /* 0x100 */ void (__stdcall *grim_set_uv)(float u0, float v0, float u1, float v1);
    /* 0x104 */ void (__stdcall *grim_set_atlas_frame)(int atlas_size, int frame);
    /* 0x108 */ void (__stdcall *grim_set_sub_rect)(int atlas_size, int width, int height, int frame);
    /* 0x10c */ void (__stdcall *grim_set_uv_point)(int index, float u, float v);
    /* 0x110 */ void (__stdcall *grim_set_color_ptr)(float * rgba);
    /* 0x114 */ void (__stdcall *grim_set_color)(float r, float g, float b, float a);
    /* 0x118 */ void (__stdcall *grim_set_color_slot)(int index, float r, float g, float b, float a);
    /* 0x11c */ void (__stdcall *grim_draw_quad)(float x, float y, float w, float h);
    /* 0x120 */ void (__stdcall *grim_draw_quad_xy)(float * xy, float w, float h);
    /* 0x124 */ void (__stdcall *grim_draw_quad_rotated_matrix)(float x, float y, float w, float h);
    /* 0x128 */ void (__stdcall *grim_submit_vertices_transform)(float * verts, int count, float * offset, float * matrix);
    /* 0x12c */ void (__stdcall *grim_submit_vertices_offset)(float * verts, int count, float * offset);
    /* 0x130 */ void (__stdcall *grim_submit_vertices_offset_color)(float * verts, int count, float * offset, float * color);
    /* 0x134 */ void (__stdcall *grim_submit_vertices_transform_color)(float * verts, int count, float * offset, float * matrix, float * color);
    /* 0x138 */ void (__stdcall *grim_draw_quad_points)(float x0, float y0, float x1, float y1, float x2, float y2, float x3, float y3);
    /* 0x13c */ void (__stdcall *grim_draw_text_mono)(float x, float y, char * text);
    /* 0x140 */ void (*grim_draw_text_mono_fmt)(IGrim2D *self, float x, float y, char * fmt, ...);
    /* 0x144 */ void (__stdcall *grim_draw_text_small)(float x, float y, char * text);
    /* 0x148 */ void (*grim_draw_text_small_fmt)(IGrim2D *self, float x, float y, char * fmt, ...);
    /* 0x14c */ int (__stdcall *grim_measure_text_width)(char * text);
};

#endif
