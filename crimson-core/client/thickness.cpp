// The RTX creature shader's part-size proxy (src/crimson/render/rtx/creature_translucency.py):
// per atlas texel, the largest fully contained odd square of opaque texels
// covering it inside its 8x8-grid cell, capped at 31 texels, stored as
// (radius + 1) * 16. Nested square openings: erode each level, then dilate the
// seeds back down from the largest. Shifts wrap at the image's edges, as PIL's
// ImageChops.offset does; cell borders are cleared after the first level.
#include "client.h"
#include <algorithm>

namespace {
using Plane = std::vector<unsigned char>;

// A 3x3 minimum or maximum, separable, wrapping at the image's edges.
template <class Pick> Plane neighborhood(const Plane &in, int width, int height, Pick pick) {
  Plane across(in.size()), out(in.size());
  for (int y = 0; y < height; ++y)
    for (int x = 0; x < width; ++x) {
      const unsigned char *row = &in[(size_t)y * width];
      across[(size_t)y * width + x] = pick(pick(row[x], row[(x + width - 1) % width]), row[(x + 1) % width]);
    }
  for (int y = 0; y < height; ++y)
    for (int x = 0; x < width; ++x)
      out[(size_t)y * width + x] = pick(pick(across[(size_t)y * width + x], across[(size_t)((y + height - 1) % height) * width + x]),
                                        across[(size_t)((y + 1) % height) * width + x]);
  return out;
}
unsigned char low(unsigned char a, unsigned char b) { return std::min(a, b); }
unsigned char high(unsigned char a, unsigned char b) { return std::max(a, b); }
} // namespace

std::vector<unsigned char> renderer_thickness(const unsigned char *bgra, int width, int height) {
  int cell_width = width / 8, cell_height = height / 8;
  Plane interior((size_t)width * height, 255), mask((size_t)width * height);
  for (int y = 0; y < height; ++y)
    for (int x = 0; x < width; ++x) {
      bool border = x % cell_width == 0 || x % cell_width == cell_width - 1 || y % cell_height == 0 ||
                    y % cell_height == cell_height - 1;
      interior[(size_t)y * width + x] = border ? 0 : 255;
      mask[(size_t)y * width + x] = bgra[((size_t)y * width + x) * 4 + 3] >= 4 ? 16 : 0;
    }
  std::vector<Plane> erosions;
  for (int level = 0; level < 16 && std::any_of(mask.begin(), mask.end(), [](unsigned char v) { return v; }); ++level) {
    erosions.push_back(mask);
    mask = neighborhood(mask, width, height, low);
    for (size_t i = 0; i < mask.size(); ++i)
      mask[i] = std::min(mask[i], interior[i]);
  }
  Plane thickness((size_t)width * height);
  for (int radius = (int)erosions.size() - 1; radius >= 0; --radius) {
    thickness = neighborhood(thickness, width, height, high);
    unsigned char encoded = (unsigned char)std::min(255, (radius + 1) * 16);
    for (size_t i = 0; i < thickness.size(); ++i)
      if (erosions[radius][i])
        thickness[i] = std::max(thickness[i], encoded);
  }
  return thickness;
}

// A box blur inside each 8x8-grid cell, as creature_translucency.py's blur_cells
// (PIL's BoxBlur): horizontal then vertical, each rounded to a byte, the cell's
// edge texels extended, so no animation frame bleeds into its neighbor.
std::vector<unsigned char> renderer_blur_cells(const std::vector<unsigned char> &plane, int width, int height, int radius) {
  int cell_width = width / 8, cell_height = height / 8, span = 2 * radius + 1;
  auto pass = [&](const Plane &in, bool vertical) {
    Plane out(in.size());
    for (int y = 0; y < height; ++y)
      for (int x = 0; x < width; ++x) {
        int along = vertical ? y : x, cell = vertical ? cell_height : cell_width, lo = along / cell * cell;
        int sum = 0;
        for (int k = -radius; k <= radius; ++k) {
          int at = std::clamp(along + k, lo, lo + cell - 1);
          sum += in[vertical ? (size_t)at * width + x : (size_t)y * width + at];
        }
        out[(size_t)y * width + x] = (unsigned char)((sum + span / 2) / span);
      }
    return out;
  };
  return pass(pass(plane, false), true);
}

// Monster Vision's continuous silhouette density (build_heat_density): two
// cell-local 5x5 alpha blurs, preserving fractional coverage. A pose's part
// sizes can jump by an entire square-opening level; density changes smoothly.
std::vector<unsigned char> renderer_heat_density(const unsigned char *bgra, int width, int height) {
  Plane alpha((size_t)width * height);
  for (size_t i = 0; i < alpha.size(); ++i)
    alpha[i] = bgra[i * 4 + 3];
  return renderer_blur_cells(renderer_blur_cells(alpha, width, height, 2), width, height, 2);
}
