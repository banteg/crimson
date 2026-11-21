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
  if (width <= 0 || height <= 0 || width % 8 != 0 || height % 8 != 0)
    return {};
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

namespace {
// A box blur inside each 8x8-grid cell, as creature_translucency.py's blur_cells
// (PIL's BoxBlur): horizontal then vertical, each rounded to a byte, the cell's
// edge texels extended, so no animation frame bleeds into its neighbor.
Plane blur_cells(const Plane &plane, int width, int height, int radius) {
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
} // namespace

// Packed RGBA8 creature surface map (creature_translucency.py's build_creature_surface_map):
// R = thickness proxy, GB = cell-clamped alpha-aware luminance gradient (128 = 0, +-127 = +-0.5;
// transparent neighbors clamp to the center texel and 1-ring transparent texels inherit in-cell
// opaque gradients so bilinear filtering at silhouettes never bleeds black background cliffs),
// A = 255 iff every texel in the 5x5 neighborhood is opaque (alpha == 255) strictly inside its 8x8 cell.
std::vector<unsigned char> renderer_creature_surface(const unsigned char *bgra, int width, int height) {
  if (width <= 0 || height <= 0 || width % 8 != 0 || height % 8 != 0)
    return {};
  int cell_width = width / 8, cell_height = height / 8;
  Plane thickness = renderer_thickness(bgra, width, height);
  size_t count = (size_t)width * height;
  std::vector<int> luma(count);
  Plane alpha(count), horiz_opaque(count), gx(count, 128), gy(count, 128);
  for (size_t i = 0; i < count; ++i) {
    unsigned char b = bgra[i * 4 + 0];
    unsigned char g = bgra[i * 4 + 1];
    unsigned char r = bgra[i * 4 + 2];
    unsigned char a = bgra[i * 4 + 3];
    alpha[i] = a;
    luma[i] = a > 0 ? (299 * (int)r + 587 * (int)g + 114 * (int)b) : 0;
  }
  for (int y = 0; y < height; ++y) {
    for (int x = 0; x < width; ++x) {
      int x0 = (x / cell_width) * cell_width, x1 = x0 + cell_width - 1;
      bool ok = x >= x0 + 2 && x <= x1 - 2;
      for (int dx = -2; ok && dx <= 2; ++dx)
        ok = alpha[(size_t)y * width + (x + dx)] == 255;
      horiz_opaque[(size_t)y * width + x] = ok ? 255 : 0;
    }
  }
  auto encode_grad = [](int diff) -> unsigned char {
    int scaled = diff * 254;
    int q = scaled >= 0 ? (scaled + 255000) / 510000 : -((-scaled + 255000) / 510000);
    return (unsigned char)std::clamp(128 + q, 1, 255);
  };
  for (int y = 0; y < height; ++y) {
    int y0 = (y / cell_height) * cell_height, y1 = y0 + cell_height - 1;
    int y_lo = std::max(y0, y - 1), y_hi = std::min(y1, y + 1);
    for (int x = 0; x < width; ++x) {
      size_t i = (size_t)y * width + x;
      if (!alpha[i])
        continue;
      int x0 = (x / cell_width) * cell_width, x1 = x0 + cell_width - 1;
      int x_lo = std::max(x0, x - 1), x_hi = std::min(x1, x + 1);
      int center = luma[i];
      int l_xlo = alpha[(size_t)y * width + x_lo] ? luma[(size_t)y * width + x_lo] : center;
      int l_xhi = alpha[(size_t)y * width + x_hi] ? luma[(size_t)y * width + x_hi] : center;
      int l_ylo = alpha[(size_t)y_lo * width + x] ? luma[(size_t)y_lo * width + x] : center;
      int l_yhi = alpha[(size_t)y_hi * width + x] ? luma[(size_t)y_hi * width + x] : center;
      gx[i] = encode_grad(l_xhi - l_xlo);
      gy[i] = encode_grad(l_yhi - l_ylo);
    }
  }
  std::vector<unsigned char> out(count * 4);
  for (int y = 0; y < height; ++y) {
    int y0 = (y / cell_height) * cell_height, y1 = y0 + cell_height - 1;
    bool y_inner = y >= y0 + 2 && y <= y1 - 2;
    for (int x = 0; x < width; ++x) {
      int x0 = (x / cell_width) * cell_width, x1 = x0 + cell_width - 1;
      size_t i = (size_t)y * width + x;
      unsigned char gx_out = gx[i], gy_out = gy[i];
      if (!alpha[i]) {
        int sum_x = 0, sum_y = 0, n = 0;
        for (int ny = std::max(y0, y - 1); ny <= std::min(y1, y + 1); ++ny)
          for (int nx = std::max(x0, x - 1); nx <= std::min(x1, x + 1); ++nx) {
            size_t ni = (size_t)ny * width + nx;
            if (alpha[ni]) {
              sum_x += gx[ni];
              sum_y += gy[ni];
              ++n;
            }
          }
        if (n) {
          gx_out = (unsigned char)((sum_x + n / 2) / n);
          gy_out = (unsigned char)((sum_y + n / 2) / n);
        }
      }
      bool opaque_5x5 = y_inner;
      for (int dy = -2; opaque_5x5 && dy <= 2; ++dy)
        opaque_5x5 = horiz_opaque[(size_t)(y + dy) * width + x] == 255;
      out[i * 4 + 0] = thickness[i];
      out[i * 4 + 1] = gx_out;
      out[i * 4 + 2] = gy_out;
      out[i * 4 + 3] = opaque_5x5 ? 255 : 0;
    }
  }
  return out;
}

// Monster Vision's continuous silhouette density (build_heat_density): two
// cell-local 5x5 alpha blurs, preserving fractional coverage. A pose's part
// sizes can jump by an entire square-opening level; density changes smoothly.
std::vector<unsigned char> renderer_heat_density(const unsigned char *bgra, int width, int height) {
  if (width <= 0 || height <= 0 || width % 8 != 0 || height % 8 != 0)
    return {};
  Plane alpha((size_t)width * height);
  for (size_t i = 0; i < alpha.size(); ++i)
    alpha[i] = bgra[i * 4 + 3];
  return blur_cells(blur_cells(alpha, width, height, 2), width, height, 2);
}
