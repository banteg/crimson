#pragma once
#include <algorithm>
#include <array>
#include <cmath>

// A color-independent field; its resolution is in world units, not display
// pixels. One texel of margin keeps visible receivers inside the sampling grid.
struct GroundVisibility {
  static constexpr float texel = 2.f;
  float rect[4] = {};
  int width = 0, height = 0, count = 0;
  void prepare(float camera_x, float camera_y, float view_width, float view_height, int sources, bool enabled) {
    *this = {};
    if (!enabled || sources <= 0 || view_width <= 0 || view_height <= 0)
      return;
    count = std::min(sources, 32);
    rect[0] = std::floor(-camera_x / texel) * texel - texel;
    rect[1] = std::floor(-camera_y / texel) * texel - texel;
    // Fixed dimensions across camera movement: a fractional pan must not
    // reallocate the atlas when the snapped origin crosses a grid cell.
    width = (int)std::ceil(view_width / texel) + 3;
    height = (int)std::ceil(view_height / texel) + 3;
    rect[2] = width * texel;
    rect[3] = height * texel;
  }
  // Conservative union of the four sources' support, expanded by one texel
  // for interpolation. Outside it the mask is white, so no draw is needed.
  std::array<int, 4> bounds(int group, const float *positions, const float *directions,
                           const float *colors, const float *responses, const float *shapes,
                           bool beams) const {
    float lo_x = rect[0] + rect[2], lo_y = rect[1] + rect[3], hi_x = rect[0], hi_y = rect[1];
    bool any = false;
    for (int i = group * 4; i < std::min(count, group * 4 + 4); ++i) {
      const float *p = positions + i * 4, *d = directions + i * 4, *r = responses + i * 4;
      if (r[0] <= 0 && r[1] <= 0)
        continue;
      float radius = std::max(std::max(1.f, p[2]), r[2]);
      float half = std::max(0.f, d[3] * .5f);
      if (beams) half = std::max(half, shapes[i * 4 + 3]);
      float square = d[0] * d[0] + d[1] * d[1];
      float ax = square > .0001f ? d[0] / std::sqrt(square) : 1.f;
      float ay = square > .0001f ? d[1] / std::sqrt(square) : 0.f;
      float ring = colors[i * 4 + 3];
      float ex = radius + (ring > 0 ? ring : std::abs(ax) * half);
      float ey = radius + (ring > 0 ? ring : std::abs(ay) * half);
      lo_x = std::min(lo_x, p[0] - ex); lo_y = std::min(lo_y, p[1] - ey);
      hi_x = std::max(hi_x, p[0] + ex); hi_y = std::max(hi_y, p[1] + ey);
      any = true;
    }
    if (!any) return {0, 0, 0, 0};
    int x0 = std::clamp((int)std::floor((lo_x - rect[0]) / texel) - 1, 0, width);
    int y0 = std::clamp((int)std::floor((lo_y - rect[1]) / texel) - 1, 0, height);
    int x1 = std::clamp((int)std::ceil((hi_x - rect[0]) / texel) + 1, 0, width);
    int y1 = std::clamp((int)std::ceil((hi_y - rect[1]) / texel) + 1, 0, height);
    return {x0, y0, std::max(0, x1 - x0), std::max(0, y1 - y0)};
  }
};
