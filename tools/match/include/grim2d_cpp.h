#ifndef GRIM2D_CPP_H
#define GRIM2D_CPP_H

// Recovered C++ view of the Grim2D interface through the primary quad slot.
// The C ABI view lives in third_party/headers/grim2d.h; this declaration is
// used when reproducing the original __thiscall virtual dispatch.
class IGrim2D_cpp {
public:
    virtual void grim_release(void) = 0;
    virtual void grim_set_paused(int paused) = 0;
    virtual float grim_get_version(void) = 0;
    virtual int grim_check_device(void) = 0;
    virtual int grim_apply_config(void) = 0;
    virtual int grim_init_system(void) = 0;
    virtual void grim_shutdown(void) = 0;
    virtual void grim_apply_settings(void) = 0;
    virtual void grim_set_config_var(unsigned int id, unsigned int value, ...) = 0;
    virtual void grim_get_config_var(unsigned int *out, int id) = 0;
    virtual char *grim_get_error_text(void) = 0;
    virtual void grim_clear_color(float r, float g, float b, float a) = 0;
    virtual int grim_set_render_target(int target_index) = 0;
    virtual int grim_get_time_ms(void) = 0;
    virtual void grim_set_time_ms(int ms) = 0;
    virtual float grim_get_frame_dt(void) = 0;
    virtual float grim_get_fps(void) = 0;
    virtual int grim_is_key_down(unsigned int key) = 0;
    virtual int grim_was_key_pressed(unsigned int key) = 0;
    virtual void grim_flush_input(void) = 0;
    virtual int grim_get_key_char(void) = 0;
    virtual void grim_set_key_char_buffer(unsigned char *buffer, int *count, int size) = 0;
    virtual int grim_is_mouse_button_down(int button) = 0;
    virtual int grim_was_mouse_button_pressed(int button) = 0;
    virtual float grim_get_mouse_wheel_delta(void) = 0;
    virtual void grim_set_mouse_pos(float x, float y) = 0;
    virtual float grim_get_mouse_x(void) = 0;
    virtual float grim_get_mouse_y(void) = 0;
    virtual float grim_get_mouse_dx(void) = 0;
    virtual float grim_get_mouse_dy(void) = 0;
    virtual float grim_get_mouse_dx_indexed(int index) = 0;
    virtual float grim_get_mouse_dy_indexed(int index) = 0;
    virtual int grim_is_key_active(int key) = 0;
    virtual float grim_get_config_float(int id) = 0;
    virtual float grim_get_slot_float(int index) = 0;
    virtual int grim_get_slot_int(int index) = 0;
    virtual void grim_set_slot_float(int index, float value) = 0;
    virtual void grim_set_slot_int(int index, int value) = 0;
    virtual int grim_get_joystick_x(void) = 0;
    virtual int grim_get_joystick_y(void) = 0;
    virtual int grim_get_joystick_z(void) = 0;
    virtual int grim_get_joystick_pov(int index) = 0;
    virtual int grim_is_joystick_button_down(int button) = 0;
    virtual int grim_create_texture(char *name, int width, int height) = 0;
    virtual int grim_recreate_texture(int handle) = 0;
    virtual int grim_load_texture(char *name, char *path) = 0;
    virtual int grim_validate_texture(int handle) = 0;
    virtual void grim_destroy_texture(int handle) = 0;
    virtual int grim_get_texture_handle(char *name) = 0;
    virtual void grim_bind_texture(int handle, int stage);
    virtual void grim_draw_fullscreen_quad(void) = 0;
    virtual void grim_draw_fullscreen_color(float r, float g, float b, float a) = 0;
    virtual void grim_draw_rect_filled(
        float *xy, float width, float height, float *rgba);
    virtual void grim_draw_rect_outline(float *xy, float width, float height) = 0;
    virtual void grim_draw_circle_filled(float x, float y, float radius) = 0;
    virtual void grim_draw_circle_outline(float x, float y, float radius) = 0;
    virtual void grim_draw_line(float *p0, float *p1, float thickness) = 0;
    virtual void grim_draw_line_quad(float *p0, float *p1, float *half_vec) = 0;
    virtual void grim_begin_batch(void);
    virtual void grim_flush_batch(void);
    virtual void grim_end_batch(void);
    virtual void grim_submit_vertex_raw(float *vertex) = 0;
    virtual void grim_submit_quad_raw(float *vertices) = 0;
    virtual void grim_set_rotation(float radians) = 0;
    virtual void grim_set_uv(float u0, float v0, float u1, float v1);
    virtual void grim_set_atlas_frame(int atlas_size, int frame) = 0;
    virtual void grim_set_sub_rect(int atlas_size, int width, int height, int frame) = 0;
    virtual void grim_set_uv_point(int index, float u, float v);
    virtual void grim_set_color_ptr(float *rgba);
    virtual void grim_set_color(float r, float g, float b, float a);
    virtual void grim_set_color_slot(
        int index, float r, float g, float b, float a);
    virtual void grim_draw_quad(float x, float y, float w, float h);
    virtual void grim_draw_quad_xy(float *xy, float w, float h);
    virtual void grim_draw_quad_rotated_matrix(float x, float y, float w, float h) = 0;
    virtual void grim_submit_vertices_transform(
        float *vertices, int count, float *offset, float *matrix);
    virtual void grim_submit_vertices_offset(
        float *vertices, int count, float *offset);
    virtual void grim_submit_vertices_offset_color(
        float *vertices,
        int count,
        float *offset,
        unsigned long *color);
    virtual void grim_submit_vertices_transform_color(
        float *vertices,
        int count,
        float *offset,
        float *matrix,
        unsigned long *color);
    virtual void grim_draw_quad_points(
        float x0,
        float y0,
        float x1,
        float y1,
        float x2,
        float y2,
        float x3,
        float y3);
    virtual void grim_draw_text_mono(float x, float y, char *text) = 0;
    virtual void grim_draw_text_mono_fmt(float x, float y, char *fmt, ...);
    virtual void grim_draw_text_small(float x, float y, char *text) = 0;
    virtual void grim_draw_text_small_fmt(float x, float y, char *fmt, ...);
};

#endif
