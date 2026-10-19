#pragma once
#include <array>
#include <vector>
struct IGrim2D_cpp {
  int texture = 0;
  std::array<float, 4> color{};
  std::vector<std::array<float, 4>> projectile_colors;
  void grim_set_color(float r, float g, float b, float a) { color = {r, g, b, a}; }
  void grim_bind_texture(int id, int) { texture = id; }
  void grim_draw_quad(float, float, float, float) {
    if (texture == 103) projectile_colors.push_back(color);
  }
  void grim_set_color_slot(int, float, float, float, float) {}
  void grim_set_uv(float, float, float, float) {}
  void grim_set_uv_point(int, float, float) {}
  void grim_set_atlas_frame(int, int) {}
  void grim_set_rotation(float) {}
  void grim_set_config_var(int, unsigned int) {}
  void grim_draw_quad_points(float, float, float, float, float, float, float, float) {}
  void grim_begin_batch() {}
  void grim_end_batch() {}
};
