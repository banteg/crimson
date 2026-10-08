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

// renderer.cpp: the Direct3D 8 subset the game module's device sends.
void renderer_init();
// The back buffer to the window's framebuffer, which stays bound for the swap
// (macOS shows a black window when the swap finds another framebuffer bound);
// renderer_resume binds the game's render target again after it.
void renderer_present(int window_width, int window_height);
void renderer_resume();
// The rectangle of the window the back buffer fills, letterboxed.
struct Viewport {
  float x, y, width, height;
  int back_width, back_height;
};
Viewport renderer_viewport(int window_width, int window_height);
std::vector<unsigned char> renderer_capture(int &width, int &height);

// audio.cpp: plays the module's mix, pulled after each frame.
void audio_init();
void audio_update(w2c_game *game);
