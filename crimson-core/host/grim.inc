#ifndef CRIMSON_GAME
void IGrim2D_cpp::grim_bind_texture(int handle, int stage) {}
void IGrim2D_cpp::grim_draw_fullscreen_quad(int unused) {}
void IGrim2D_cpp::grim_draw_fullscreen_color(float r, float g, float b,
                                             float a) {}
void IGrim2D_cpp::grim_draw_rect_filled(float *xy, float width, float height,
                                        float *rgba) {}
void IGrim2D_cpp::grim_draw_rect_outline(float *xy, float width, float height) {
}
void IGrim2D_cpp::grim_begin_batch(void) {}
void IGrim2D_cpp::grim_flush_batch(void) {}
void IGrim2D_cpp::grim_end_batch(void) {}
void IGrim2D_cpp::grim_set_rotation(float radians) {}
void IGrim2D_cpp::grim_set_uv(float u0, float v0, float u1, float v1) {}
void IGrim2D_cpp::grim_set_uv_point(int index, float u, float v) {}
void IGrim2D_cpp::grim_set_color_ptr(float *rgba) {}
void IGrim2D_cpp::grim_set_color(float r, float g, float b, float a) {}
void IGrim2D_cpp::grim_set_color_slot(int index, float r, float g, float b,
                                      float a) {}
void IGrim2D_cpp::grim_draw_quad(float x, float y, float w, float h) {}
void IGrim2D_cpp::grim_draw_quad_xy(float *xy, float w, float h) {}
void IGrim2D_cpp::grim_draw_quad_rotated_matrix(float x, float y, float w,
                                                float h) {}
void IGrim2D_cpp::grim_submit_vertices_transform(float *vertices, int count,
                                                 float *offset, float *matrix) {
}
void IGrim2D_cpp::grim_submit_vertices_offset(float *vertices, int count,
                                              float *offset) {}
void IGrim2D_cpp::grim_submit_vertices_offset_color(float *vertices, int count,
                                                    float *offset,
                                                    unsigned long *color) {}
void IGrim2D_cpp::grim_submit_vertices_transform_color(float *vertices,
                                                       int count, float *offset,
                                                       float *matrix,
                                                       unsigned long *color) {}
void IGrim2D_cpp::grim_draw_quad_points(float x0, float y0, float x1, float y1,
                                        float x2, float y2, float x3,
                                        float y3) {}
void IGrim2D_cpp::grim_draw_text_mono_fmt(float x, float y, char *fmt, ...) {}
void IGrim2D_cpp::grim_draw_text_small_fmt(float x, float y, char *fmt, ...) {}
#endif
class HeadlessGrim final : public IGrim2D_cpp {
public:
  void grim_release(void) override {}
  void grim_set_paused(int paused) override {}
  float grim_get_version(void) override { return 0; }
  bool grim_save_screenshot(char *path) override { return 0; }
  bool grim_apply_config(void) override { return 0; }
  bool grim_init_system(void) override { return 0; }
  void grim_shutdown(void) override {}
  bool grim_apply_settings(void) override { return 0; }
  void grim_set_config_var(unsigned int id,
                           grim_config_value_t value) override {}
  grim_config_value_t grim_get_config_var(int id) override {
    return grim_config_value_t(0u);
  }
  char *grim_get_error_text(void) override { return nullptr; }
  void grim_clear_color(float r, float g, float b, float a) override {}
  bool grim_set_render_target(int target_index) override { return 0; }
  int grim_get_time_ms(void) override { return 0; }
  void grim_set_time_ms(int ms) override {}
  float grim_get_frame_dt(void) override { return 0; }
  float grim_get_fps(void) override { return 0; }
  unsigned char grim_is_key_down(unsigned char key) override { return 0; }
  bool grim_was_key_pressed(unsigned int key) override { return 0; }
  void grim_flush_input(void) override {}
  int grim_get_key_char(void) override { return 0; }
  void grim_set_key_char_buffer(unsigned char *buffer, int *count,
                                int size) override {}
  unsigned char grim_is_mouse_button_down(int button) override { return 0; }
  bool grim_was_mouse_button_pressed(int button) override { return false; }
  float grim_get_mouse_wheel_delta(void) override { return 0; }
  void grim_set_mouse_pos(float x, float y) override {}
  float grim_get_mouse_x(void) override { return in.aim_x; }
  float grim_get_mouse_y(void) override { return in.aim_y; }
  float grim_get_mouse_dx(void) override { return 0; }
  float grim_get_mouse_dy(void) override { return 0; }
  float grim_get_mouse_dx_indexed(int index) override { return 0; }
  float grim_get_mouse_dy_indexed(int index) override { return 0; }
  unsigned char grim_is_key_active(int key) override {
    return key == 100   ? (in.flags & 1) != 0
           : key == 101 ? (in.flags & (65536 | 4)) != 0
           : key == 102 ? menu_requested
           : key == 34  ? (in.flags & 131072) != 0
           // The player's move and aim keys (host.cpp) and their recorded bits.
           : key == 0x100 ? (in.flags & 16) != 0
           : key == 0x101 ? (in.flags & 32) != 0
           : key == 0x102 ? (in.flags & 64) != 0
           : key == 0x103 ? (in.flags & 128) != 0
           : key == 0x104 ? (in.flags & 1u << 18) != 0
           : key == 0x105 ? (in.flags & 1u << 19) != 0
                          : 0;
  }
  float grim_get_config_float(int id) override {
    return id == 0 ? in.move_x : id == 1 ? in.move_y : 0.0f;
  }
  float grim_get_slot_float(int index) override { return 0; }
  int grim_get_slot_int(int index) override { return 0; }
  void grim_set_slot_float(int index, float value) override {}
  void grim_set_slot_int(int index, int value) override {}
  int grim_get_joystick_x(void) override { return 0; }
  int grim_get_joystick_y(void) override { return 0; }
  int grim_get_joystick_z(void) override { return 0; }
  int grim_get_joystick_pov(int index) override { return 0; }
  unsigned char grim_is_joystick_button_down(int button) override { return 0; }
  bool grim_create_texture(char *name, int width, int height) override {
    return 0;
  }
  bool grim_recreate_texture(int handle) override { return 0; }
  bool grim_load_texture(char *name, char *path) override { return 0; }
  bool grim_save_texture(int handle, char *path) override { return 0; }
  void grim_destroy_texture(int handle) override {}
  int grim_get_texture_handle(char *name) override { return 1; }
  void grim_bind_texture(int handle, int stage) override {}
  void grim_draw_fullscreen_quad(int unused) override {}
  void grim_draw_fullscreen_color(float r, float g, float b, float a) override {
  }
  void grim_draw_rect_filled(float *xy, float width, float height,
                             float *rgba) override {}
  void grim_draw_rect_outline(float *xy, float width, float height) override {}
  void grim_draw_circle_filled(float x, float y, float radius) override {}
  void grim_draw_circle_outline(float x, float y, float radius) override {}
  void grim_draw_line(float *p0, float *p1, float thickness) override {}
  void grim_draw_line_quad(float *p0, float *p1, float *half_vec) override {}
  void grim_begin_batch(void) override {}
  void grim_flush_batch(void) override {}
  void grim_end_batch(void) override {}
  void grim_submit_vertex_raw(float *vertex) override {}
  void grim_submit_quad_raw(float *vertices) override {}
  void grim_set_rotation(float radians) override {}
  void grim_set_uv(float u0, float v0, float u1, float v1) override {}
  void grim_set_atlas_frame(int atlas_size, int frame) override {}
  void grim_set_sub_rect(int atlas_size, int width, int height,
                         int frame) override {}
  void grim_set_uv_point(int index, float u, float v) override {}
  void grim_set_color_ptr(float *rgba) override {}
  void grim_set_color(float r, float g, float b, float a) override {}
  void grim_set_color_slot(int index, float r, float g, float b,
                           float a) override {}
  void grim_draw_quad(float x, float y, float w, float h) override {}
  void grim_draw_quad_xy(float *xy, float w, float h) override {}
  void grim_draw_quad_rotated_matrix(float x, float y, float w,
                                     float h) override {}
  void grim_submit_vertices_transform(float *vertices, int count, float *offset,
                                      float *matrix) override {}
  void grim_submit_vertices_offset(float *vertices, int count,
                                   float *offset) override {}
  void grim_submit_vertices_offset_color(float *vertices, int count,
                                         float *offset,
                                         unsigned long *color) override {}
  void grim_submit_vertices_transform_color(float *vertices, int count,
                                            float *offset, float *matrix,
                                            unsigned long *color) override {}
  void grim_draw_quad_points(float x0, float y0, float x1, float y1, float x2,
                             float y2, float x3, float y3) override {}
  void grim_draw_text_mono(float x, float y, char *text) override {}
  void grim_draw_text_mono_fmt(float x, float y, char *fmt, ...) override {}
  void grim_draw_text_small(float x, float y, char *text) override {}
  void grim_draw_text_small_fmt(float x, float y, char *fmt, ...) override {}
  int grim_measure_text_width(char *text) override { return 0; }
};
static HeadlessGrim headless_grim;
