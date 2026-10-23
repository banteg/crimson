#pragma once
// The client host: one game module (game.wasm through wasm2c), an SDL3 window,
// and the OpenGL renderer behind the module's host interface.
#include "game.h"
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
std::vector<unsigned char> renderer_capture(int &width, int &height);
// RTX (game/rtx.cpp): whether the renderer shows it, asked to, and the display's
// EDR headroom its tonemap rolls highlights toward (1 is SDR).
bool renderer_set_rtx(bool enabled);
void renderer_set_headroom(float headroom);
// thickness.cpp: an 8x8-cell creature atlas's part sizes for RTX transmission.
std::vector<unsigned char> renderer_thickness(const unsigned char *bgra, int width, int height);

// audio.cpp: plays the module's mix, pulled after each frame.
void audio_init();
void audio_update(w2c_game *game);
