/* Auto-generated from analysis/ghidra/derived/grim2d_vtable_map.json. */
#ifndef GRIM2D_H
#define GRIM2D_H

typedef struct IGrim2D_vtbl IGrim2D_vtbl;
typedef struct IGrim2D IGrim2D;

struct IGrim2D {
    IGrim2D_vtbl *vtable;
};

struct IGrim2D_vtbl {
    /* 0x000 */ void (*grim_release)(IGrim2D *self);
    /* 0x004 */ void (*grim_set_paused)(IGrim2D *self, int paused);
    /* 0x008 */ float (*grim_get_version)(IGrim2D *self);
    /* 0x00c */ int (*grim_check_device)(IGrim2D *self);
    /* 0x010 */ int (*grim_apply_config)(IGrim2D *self);
    /* 0x014 */ int (*grim_init_system)(IGrim2D *self);
    /* 0x018 */ void (*grim_shutdown)(IGrim2D *self);
    /* 0x01c */ void (*grim_apply_settings)(IGrim2D *self);
    /* 0x020 */ void (*grim_set_config_var)(IGrim2D *self, unsigned int id, unsigned int value);
    /* 0x024 */ void (*grim_get_config_var)(IGrim2D *self, unsigned int * out, int id);
    /* 0x028 */ char * (*grim_get_error_text)(IGrim2D *self);
    /* 0x02c */ void (*grim_clear_color)(IGrim2D *self, float r, float g, float b, float a);
    /* 0x030 */ int (*grim_set_render_target)(IGrim2D *self, int target_index);
    /* 0x034 */ int (*grim_get_time_ms)(IGrim2D *self);
    /* 0x038 */ void (*grim_set_time_ms)(IGrim2D *self, int ms);
    /* 0x03c */ float (*grim_get_frame_dt)(IGrim2D *self);
    /* 0x040 */ float (*grim_get_fps)(IGrim2D *self);
    /* 0x044 */ int (*grim_is_key_down)(IGrim2D *self, unsigned int key);
    /* 0x048 */ int (*grim_was_key_pressed)(IGrim2D *self, unsigned int key);
    /* 0x04c */ void (*grim_flush_input)(IGrim2D *self);
    /* 0x050 */ int (*grim_get_key_char)(IGrim2D *self);
    /* 0x054 */ void (*grim_set_key_char_buffer)(IGrim2D *self, unsigned char * buffer, int * count, int size);
    /* 0x058 */ int (*grim_is_mouse_button_down)(IGrim2D *self, int button);
    /* 0x05c */ int (*grim_was_mouse_button_pressed)(IGrim2D *self, int button);
    /* 0x060 */ float (*grim_get_mouse_wheel_delta)(IGrim2D *self);
    /* 0x064 */ void (*grim_set_mouse_pos)(IGrim2D *self, float x, float y);
    /* 0x068 */ float (*grim_get_mouse_x)(IGrim2D *self);
    /* 0x06c */ float (*grim_get_mouse_y)(IGrim2D *self);
    /* 0x070 */ float (*grim_get_mouse_dx)(IGrim2D *self);
    /* 0x074 */ float (*grim_get_mouse_dy)(IGrim2D *self);
    /* 0x078 */ float (*grim_get_mouse_dx_indexed)(IGrim2D *self, int index);
    /* 0x07c */ float (*grim_get_mouse_dy_indexed)(IGrim2D *self, int index);
    /* 0x080 */ int (*grim_is_key_active)(IGrim2D *self, int key);
    /* 0x084 */ float (*grim_get_config_float)(IGrim2D *self, int id);
    /* 0x088 */ float (*grim_get_slot_float)(IGrim2D *self, int index);
    /* 0x08c */ int (*grim_get_slot_int)(IGrim2D *self, int index);
    /* 0x090 */ void (*grim_set_slot_float)(IGrim2D *self, int index, float value);
    /* 0x094 */ void (*grim_set_slot_int)(IGrim2D *self, int index, int value);
    /* 0x098 */ int (*grim_get_joystick_x)(IGrim2D *self);
    /* 0x09c */ int (*grim_get_joystick_y)(IGrim2D *self);
    /* 0x0a0 */ int (*grim_get_joystick_z)(IGrim2D *self);
    /* 0x0a4 */ int (*grim_get_joystick_pov)(IGrim2D *self, int index);
    /* 0x0a8 */ int (*grim_is_joystick_button_down)(IGrim2D *self, int button);
    /* 0x0ac */ int (*grim_create_texture)(IGrim2D *self, char * name, int width, int height);
    /* 0x0b0 */ int (*grim_recreate_texture)(IGrim2D *self, int handle);
    /* 0x0b4 */ int (*grim_load_texture)(IGrim2D *self, char * name, char * path);
    /* 0x0b8 */ int (*grim_validate_texture)(IGrim2D *self, int handle);
    /* 0x0bc */ void (*grim_destroy_texture)(IGrim2D *self, int handle);
    /* 0x0c0 */ int (*grim_get_texture_handle)(IGrim2D *self, char * name);
    /* 0x0c4 */ void (*grim_bind_texture)(IGrim2D *self, int handle, int stage);
    /* 0x0c8 */ void (*grim_draw_fullscreen_quad)(IGrim2D *self);
    /* 0x0cc */ void (*grim_draw_fullscreen_color)(IGrim2D *self, float r, float g, float b, float a);
    /* 0x0d0 */ void (*grim_draw_rect_filled)(IGrim2D *self, float * xy, float w, float h);
    /* 0x0d4 */ void (*grim_draw_rect_outline)(IGrim2D *self, float * xy, float w, float h);
    /* 0x0d8 */ void (*grim_draw_circle_filled)(IGrim2D *self, float x, float y, float radius);
    /* 0x0dc */ void (*grim_draw_circle_outline)(IGrim2D *self, float x, float y, float radius);
    /* 0x0e0 */ void (*grim_draw_line)(IGrim2D *self, float * p0, float * p1, float thickness);
    /* 0x0e4 */ void (*grim_draw_line_quad)(IGrim2D *self, float * p0, float * p1, float * half_vec);
    /* 0x0e8 */ void (*grim_begin_batch)(IGrim2D *self);
    /* 0x0ec */ void (*grim_flush_batch)(IGrim2D *self);
    /* 0x0f0 */ void (*grim_end_batch)(IGrim2D *self);
    /* 0x0f4 */ void (*grim_submit_vertex_raw)(IGrim2D *self, float * vertex);
    /* 0x0f8 */ void (*grim_submit_quad_raw)(IGrim2D *self, float * verts);
    /* 0x0fc */ void (*grim_set_rotation)(IGrim2D *self, float radians);
    /* 0x100 */ void (*grim_set_uv)(IGrim2D *self, float u0, float v0, float u1, float v1);
    /* 0x104 */ void (*grim_set_atlas_frame)(IGrim2D *self, int atlas_size, int frame);
    /* 0x108 */ void (*grim_set_sub_rect)(IGrim2D *self, int atlas_size, int width, int height, int frame);
    /* 0x10c */ void (*grim_set_uv_point)(IGrim2D *self, int index, float u, float v);
    /* 0x110 */ void (*grim_set_color_ptr)(IGrim2D *self, float * rgba);
    /* 0x114 */ void (*grim_set_color)(IGrim2D *self, float r, float g, float b, float a);
    /* 0x118 */ void (*grim_set_color_slot)(IGrim2D *self, int index, float r, float g, float b, float a);
    /* 0x11c */ void (*grim_draw_quad)(IGrim2D *self, float x, float y, float w, float h);
    /* 0x120 */ void (*grim_draw_quad_xy)(IGrim2D *self, float * xy, float w, float h);
    /* 0x124 */ void (*grim_draw_quad_rotated_matrix)(IGrim2D *self, float x, float y, float w, float h);
    /* 0x128 */ void (*grim_submit_vertices_transform)(IGrim2D *self, float * verts, int count, float * offset, float * matrix);
    /* 0x12c */ void (*grim_submit_vertices_offset)(IGrim2D *self, float * verts, int count, float * offset);
    /* 0x130 */ void (*grim_submit_vertices_offset_color)(IGrim2D *self, float * verts, int count, float * offset, float * color);
    /* 0x134 */ void (*grim_submit_vertices_transform_color)(IGrim2D *self, float * verts, int count, float * offset, float * matrix, float * color);
    /* 0x138 */ void (*grim_draw_quad_points)(IGrim2D *self, float x0, float y0, float x1, float y1, float x2, float y2, float x3, float y3);
    /* 0x13c */ void (*grim_draw_text_mono)(IGrim2D *self, float x, float y, char * text);
    /* 0x140 */ void (*grim_draw_text_mono_fmt)(IGrim2D *self, float x, float y, char * fmt, ...);
    /* 0x144 */ void (*grim_draw_text_small)(IGrim2D *self, float x, float y, char * text);
    /* 0x148 */ void (*grim_draw_text_small_fmt)(IGrim2D *self, float x, float y, char * fmt, ...);
    /* 0x14c */ int (*grim_measure_text_width)(IGrim2D *self, char * text);
};

#endif
