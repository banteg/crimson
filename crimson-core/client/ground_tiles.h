#pragma once
#include "ground_visibility.h"
#include <vector>

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
    for (int i = 0; i < count; ++i) {
      const float *response = responses + 4 * i;
      if (response[0] <= 0 && response[1] <= 0)
        continue;
      auto bounds = ground_light_bounds(i, positions, directions, colors, responses, shapes, beams);
      // Keep the boundary conservative when CPU and shader rounding differ.
      constexpr float margin = .01f;
      int x0 = std::max(0, (int)std::floor((bounds[0] - margin) / tile_size));
      int y0 = std::max(0, (int)std::floor((bounds[1] - margin) / tile_size));
      int x1 = std::min(width - 1, (int)std::floor((bounds[2] + margin) / tile_size));
      int y1 = std::min(height - 1, (int)std::floor((bounds[3] + margin) / tile_size));
      for (int y = y0; y <= y1; ++y)
        for (int x = x0; x <= x1; ++x)
          masks[((size_t)y * width + x) * 4 + i / 8] |= 1 << (i % 8);
    }
  }
};
