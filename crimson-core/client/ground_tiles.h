#pragma once
#include "ground_visibility.h"
#include <vector>

inline float ground_point_box_dist_sq(float px, float py, float x0, float y0, float x1, float y1) {
  float dx = px < x0 ? x0 - px : (px > x1 ? px - x1 : 0.f);
  float dy = py < y0 ? y0 - py : (py > y1 ? py - y1 : 0.f);
  return dx * dx + dy * dy;
}

inline float ground_point_seg_dist_sq(float px, float py, float cx, float cy,
                                      float ux, float uy, float half) {
  float dx = px - cx, dy = py - cy;
  float along = std::clamp(dx * ux + dy * uy, -half, half);
  float rx = dx - ux * along, ry = dy - uy * along;
  return rx * rx + ry * ry;
}

inline bool ground_segment_intersects_box(float ax, float ay, float ex, float ey,
                                          float x0, float y0, float x1, float y1) {
  float dx = ex - ax, dy = ey - ay;
  float t0 = 0.f, t1 = 1.f;
  auto clip = [&](float p, float q) {
    if (p == 0.f)
      return q >= 0.f;
    float r = q / p;
    if (p < 0.f) {
      if (r > t1)
        return false;
      if (r > t0)
        t0 = r;
    } else {
      if (r < t0)
        return false;
      if (r < t1)
        t1 = r;
    }
    return true;
  };
  return clip(-dx, ax - x0) && clip(dx, x1 - ax) &&
         clip(-dy, ay - y0) && clip(dy, y1 - ay);
}

inline bool ground_capsule_hits_box(float cx, float cy, float ux, float uy, float half, float radius,
                                    float x0, float y0, float x1, float y1) {
  float r2 = radius * radius;
  if (half <= 0.f)
    return ground_point_box_dist_sq(cx, cy, x0, y0, x1, y1) < r2;
  float ax = cx - ux * half, ay = cy - uy * half;
  float ex = cx + ux * half, ey = cy + uy * half;
  if (ground_segment_intersects_box(ax, ay, ex, ey, x0, y0, x1, y1))
    return true;
  if (ground_point_box_dist_sq(ax, ay, x0, y0, x1, y1) < r2 ||
      ground_point_box_dist_sq(ex, ey, x0, y0, x1, y1) < r2)
    return true;
  return ground_point_seg_dist_sq(x0, y0, cx, cy, ux, uy, half) < r2 ||
         ground_point_seg_dist_sq(x1, y0, cx, cy, ux, uy, half) < r2 ||
         ground_point_seg_dist_sq(x0, y1, cx, cy, ux, uy, half) < r2 ||
         ground_point_seg_dist_sq(x1, y1, cx, cy, ux, uy, half) < r2;
}

inline bool ground_ring_hits_box(float cx, float cy, float ring, float radius,
                                 float x0, float y0, float x1, float y1) {
  float outer = ring + radius;
  if (ground_point_box_dist_sq(cx, cy, x0, y0, x1, y1) >= outer * outer)
    return false;
  float inner = ring - radius;
  if (inner <= 0.f)
    return true;
  float fx = std::max(std::abs(cx - x0), std::abs(cx - x1));
  float fy = std::max(std::abs(cy - y0), std::abs(cy - y1));
  return fx * fx + fy * fy > inner * inner;
}

// One bit per selected light. Four RGBA8 channels keep the same byte layout
// on OpenGL and WebGPU, including the light in slot 31.
struct GroundTiles {
  static constexpr int tile_size = 32;
  int width = 0, height = 0;
  std::vector<unsigned char> masks;

  void prepare(float world_width, float world_height, int count, const float *positions,
               const float *directions, const float *colors, const float *responses,
               const float *shapes, bool beams) {
    width = height = 0;
    if (!count || !(world_width > 0 && world_width <= 65536 && world_height > 0 && world_height <= 65536))
      return;
    width = (int)std::ceil(world_width / tile_size);
    height = (int)std::ceil(world_height / tile_size);
    masks.assign((size_t)width * height * 4, 0);
    // Keep the boundary conservative when CPU and shader rounding differ.
    constexpr float margin = .01f;
    for (int i = 0; i < count; ++i) {
      const float *p = positions + 4 * i, *d = directions + 4 * i;
      const float *c = colors + 4 * i, *r = responses + 4 * i;
      bool has_diff = r[0] > 0.f;
      bool has_spec = r[1] > 0.f && r[2] > 0.f;
      if (!has_diff && !has_spec)
        continue;
      float ring = c[3];
      bool is_ring = ring > 0.f;
      float square = d[0] * d[0] + d[1] * d[1];
      bool has_dir = square > .0001f;
      float inv_len = has_dir ? 1.f / std::sqrt(square) : 1.f;
      float ux = has_dir ? d[0] * inv_len : 1.f;
      float uy = has_dir ? d[1] * inv_len : 0.f;
      bool continuous = !is_ring && beams && shapes && shapes[4 * i + 3] > 0.f && has_diff;
      float spec_half = has_dir ? std::max(0.f, d[3] * .5f) : 0.f;
      float diff_half = continuous ? shapes[4 * i + 3] : spec_half;
      float diff_rad = has_diff ? std::max(1.f, p[2]) + margin : 0.f;
      float spec_rad = has_spec ? std::max(.01f, r[2]) + margin : 0.f;
      float ex, ey;
      if (is_ring) {
        ex = ey = std::max(diff_rad, spec_rad) + ring;
      } else {
        ex = std::max(has_diff ? diff_rad + std::abs(ux) * diff_half : 0.f,
                      has_spec ? spec_rad + std::abs(ux) * spec_half : 0.f);
        ey = std::max(has_diff ? diff_rad + std::abs(uy) * diff_half : 0.f,
                      has_spec ? spec_rad + std::abs(uy) * spec_half : 0.f);
      }
      int x0 = std::max(0, (int)std::floor((p[0] - ex) / tile_size));
      int y0 = std::max(0, (int)std::floor((p[1] - ey) / tile_size));
      int x1 = std::min(width - 1, (int)std::floor((p[0] + ex) / tile_size));
      int y1 = std::min(height - 1, (int)std::floor((p[1] + ey) / tile_size));
      unsigned char bit = (unsigned char)(1u << (i % 8));
      int byte = i / 8;
      float max_rad = std::max(diff_rad, spec_rad);
      bool shared_capsule = has_diff && has_spec && diff_half == spec_half;
      for (int y = y0; y <= y1; ++y) {
        float by0 = (float)(y * tile_size), by1 = by0 + tile_size;
        size_t row = (size_t)y * width;
        for (int x = x0; x <= x1; ++x) {
          float bx0 = (float)(x * tile_size), bx1 = bx0 + tile_size;
          bool hit;
          if (is_ring) {
            hit = ground_ring_hits_box(p[0], p[1], ring, max_rad, bx0, by0, bx1, by1);
          } else if (shared_capsule) {
            hit = ground_capsule_hits_box(p[0], p[1], ux, uy, diff_half, max_rad, bx0, by0, bx1, by1);
          } else {
            hit = (has_diff && ground_capsule_hits_box(p[0], p[1], ux, uy, diff_half, diff_rad, bx0, by0, bx1, by1)) ||
                  (has_spec && ground_capsule_hits_box(p[0], p[1], ux, uy, spec_half, spec_rad, bx0, by0, bx1, by1));
          }
          if (hit)
            masks[(row + x) * 4 + byte] |= bit;
        }
      }
    }
  }
};
