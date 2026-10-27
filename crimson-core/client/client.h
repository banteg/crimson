#pragma once
// The client host: one game module (game.wasm through wasm2c), an SDL3 window,
// and the OpenGL renderer behind the module's host interface.
#include "game.h"
#include <algorithm>
#include <string>
#include <vector>

u8 *client_memory();
const std::string &client_game_directory();
[[noreturn]] void client_fatal(const char *message);
void client_wasi_init();
// The host path of a name under the game directory, matched as the game opens it.
bool client_resolve(const std::string &relative, std::string &path);

// renderer.cpp: the Direct3D 8 subset the game module's device sends (in the
// browser, renderer_webgpu.cpp instead where WebGPU runs; renderer_select.cpp).
// Whether it draws with OpenGL, whose window needs a GL context and swaps.
bool renderer_uses_gl();
void renderer_init();
// Fit the logical game view to physical window pixels before the game draws.
void renderer_resize(int window_width, int window_height);
// The back buffer to the window's framebuffer, which stays bound for the swap
// (macOS shows a black window when the swap finds another framebuffer bound);
// renderer_resume binds the game's render target again after it.
void renderer_present(int window_width, int window_height);
void renderer_resume();
// Integer physical pixels, with a top-left origin shared by input and drawing.
struct Viewport {
  int x, y, width, height;
  int back_width, back_height;
  float logical_x(float pixel_x) const { return (pixel_x - x) * back_width / width; }
  float logical_y(float pixel_y) const { return (pixel_y - y) * back_height / height; }
};
Viewport renderer_viewport(int window_width, int window_height);
// The most the RTX world draws, as a multiple of the game's resolution (the
// console's rendersize; 0 for every pixel of the back buffer). By default twice
// the game's resolution, the terrain's own density: past it a large display only
// blurs less, at a GPU cost that grows with every pixel. The tonemap scales the
// world up onto the back buffer, so the HUD and its text keep the display's
// pixels, and Classic, which costs little, draws at the display's resolution.
extern float render_size;
// The RTX world's pixels for a back buffer `width` x `height` (both in, then
// out) showing `logical_width` of the game across.
inline void world_size(int logical_width, int &width, int &height) {
  double scale = render_size > 0 ? std::min(1., (double)render_size * logical_width / width) : 1.;
  width = std::max(1, (int)(width * scale + .5));
  height = std::max(1, (int)(height * scale + .5));
}
std::vector<unsigned char> renderer_capture(int &width, int &height);
// RTX (game/rtx.cpp): whether the renderer shows it, asked to, and the display's
// EDR headroom its tonemap rolls highlights toward (1 is SDR).
bool renderer_set_rtx(bool enabled);
void renderer_set_headroom(float headroom);
// CRIMSON_PROFILE (main.cpp): after the swap, the frame ends
// (renderer_frame_end); then its record, as the members of a JSON object (its
// CPU passes, draws, scene sizes and targets), and the GPU passes of frames
// whose work has finished, oldest first, a few frames later. The WebGPU
// renderer records nothing.
void renderer_frame_end();
bool renderer_profile_frame(long long &frame, std::string &record, bool &timed);
bool renderer_profile_gpu(long long &frame, std::string &passes);
// thickness.cpp: an 8x8-cell creature atlas's part sizes for RTX transmission.
std::vector<unsigned char> renderer_thickness(const unsigned char *bgra, int width, int height);
// Monster Vision's silhouette density: two cell-local 5x5 alpha blurs.
std::vector<unsigned char> renderer_heat_density(const unsigned char *bgra, int width, int height);

// audio.cpp: plays the module's mix, pulled after each frame.
void audio_init();
void audio_update(w2c_game *game);
