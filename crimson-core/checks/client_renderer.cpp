// Exercise the production renderer on a real GL context without game assets.
#include <SDL3/SDL.h>
#include <assert.h>
#include <stdlib.h>
#include "../client/renderer.cpp"

alignas(16) u8 memory[4096];
u8 *client_memory() { return memory; }
[[noreturn]] void client_fatal(const char *message) {
  fprintf(stderr, "%s\n", message);
  abort();
}

struct Vertex {
  float x, y, z, rhw;
  u32 color;
  float u, v;
};

void rectangle(float left, float top, float right, float bottom, u32 color) {
  // D3D's half-pixel adjustment remains in logical units.
  Vertex vertices[] = {{left - .5f, top - .5f, 0, 1, color, 0, 0},
                       {right - .5f, top - .5f, 0, 1, color, 1, 0},
                       {left - .5f, bottom - .5f, 0, 1, color, 0, 1},
                       {right - .5f, bottom - .5f, 0, 1, color, 1, 1}};
  memcpy(memory, vertices, sizeof vertices);
  w2c_host_draw(nullptr, 5, 0, 4, 0, 2);
}

void check_scene(int window_width, int window_height, int expected_width, int expected_height) {
  renderer_resize(window_width, window_height);
  Viewport v = renderer_viewport(window_width, window_height);
  assert(v.width == expected_width && v.height == expected_height);
  assert(v.back_width == 1024 && v.back_height == 768);
  for (float fraction : {0.f, .125f, .5f, 1.f}) {
    assert(fabsf(v.logical_x(v.x + fraction * v.width) - fraction * 1024) < .001f);
    assert(fabsf(v.logical_y(v.y + fraction * v.height) - fraction * 768) < .001f);
  }
  assert(v.logical_x(v.x - 1.f) < 0 && v.logical_y(v.y - 1.f) < 0);
  w2c_host_clear(nullptr, 0);
  rectangle(256, 192, 768, 576, 0x00ff0000);
  int width, height;
  auto pixels = renderer_capture(width, height);
  assert(width == expected_width && height == expected_height);
  // Check every pixel, including coverage boundaries and the opaque alpha.
  for (int y = 0; y < height; ++y)
    for (int x = 0; x < width; ++x) {
      bool red = x + .5f >= width * .25f && x + .5f < width * .75f &&
                 y + .5f >= height * .25f && y + .5f < height * .75f;
      size_t i = ((size_t)y * width + x) * 4;
      assert(pixels[i] == (red ? 255 : 0));
      assert(pixels[i + 1] == 0 && pixels[i + 2] == 0 && pixels[i + 3] == 255);
    }
  assert(glGetError() == GL_NO_ERROR);
}

int main() {
  assert(SDL_Init(SDL_INIT_VIDEO));
#ifdef __EMSCRIPTEN__
  SDL_GL_SetAttribute(SDL_GL_CONTEXT_PROFILE_MASK, SDL_GL_CONTEXT_PROFILE_ES);
  SDL_GL_SetAttribute(SDL_GL_CONTEXT_MAJOR_VERSION, 3);
  SDL_GL_SetAttribute(SDL_GL_CONTEXT_MINOR_VERSION, 0);
#else
  SDL_GL_SetAttribute(SDL_GL_CONTEXT_PROFILE_MASK, SDL_GL_CONTEXT_PROFILE_CORE);
  SDL_GL_SetAttribute(SDL_GL_CONTEXT_MAJOR_VERSION, 3);
  SDL_GL_SetAttribute(SDL_GL_CONTEXT_MINOR_VERSION, 3);
  SDL_GL_SetAttribute(SDL_GL_CONTEXT_FLAGS, SDL_GL_CONTEXT_FORWARD_COMPATIBLE_FLAG);
#endif
  SDL_Window *window = SDL_CreateWindow("Renderer checks", 1024, 768, SDL_WINDOW_OPENGL | SDL_WINDOW_HIDDEN);
  assert(window);
  SDL_GLContext context = SDL_GL_CreateContext(window);
  assert(context);
  renderer_init();
  renderer_resize(2048, 1536);
  w2c_host_back_buffer(nullptr, 1024, 768);
  assert(textures[0].width == 2048); // Correct on the very first draw, too.
  w2c_host_render_state(nullptr, RS_CULLMODE, 1);
  w2c_host_texture_stage_state(nullptr, 0, TSS_ALPHAOP, 3);
  check_scene(1024, 768, 1024, 768);
  check_scene(1280, 960, 1280, 960);
  check_scene(1600, 1200, 1600, 1200);
  check_scene(2048, 1536, 2048, 1536);
  check_scene(2560, 1440, 1920, 1440);
  check_scene(3840, 2160, 2880, 2160);
  check_scene(1001, 777, 1001, 751);
  check_scene(400, 300, 400, 300);
  renderer_resize(2048, 1536);
  w2c_host_clear(nullptr, 0);
  rectangle(100, 100, 100.5f, 101, 0xffffffff);
  int width, height;
  auto pixels = renderer_capture(width, height);
  // A half-logical-pixel strip occupies exactly one physical column at 2x.
  // Rendering at 1x and then enlarging could never produce this result.
  for (int y = 200; y < 202; ++y)
    for (int x = 199; x < 202; ++x)
      assert(pixels[((size_t)y * width + x) * 4] == (x == 200 ? 255 : 0));

  // Terrain is fixed at 2x logical density, independent of scene resolution.
  w2c_host_texture_create(nullptr, 7, 1024, 1024, 1);
  w2c_host_set_render_target(nullptr, 7);
  w2c_host_clear(nullptr, 0xff123456);
  rectangle(100, 100, 100.5f, 101, 0xffffffff);
  u8 baked[8];
  glReadPixels(200, 200, 2, 1, GL_RGBA, GL_UNSIGNED_BYTE, baked);
  assert(baked[0] == 255 && baked[4] == 0x12);
  w2c_host_texture_copy(nullptr, 8, 7);
  renderer_resize(1600, 1200);
  GLint viewport[4];
  glGetIntegerv(GL_VIEWPORT, viewport);
  assert(viewport[2] == 2048 && viewport[3] == 2048);
  assert(textures[7].width == 2048 && textures[8].width == 2048);
  assert(textures[8].logical_width == 1024 && textures[8].logical_height == 1024);
  w2c_host_clear(nullptr, 0);
  w2c_host_texture_copy(nullptr, 7, 8);
  u8 restored[8];
  glReadPixels(200, 200, 2, 1, GL_RGBA, GL_UNSIGNED_BYTE, restored);
  assert(!memcmp(baked, restored, sizeof baked));

  // Uploads to a scaled target read only the logical CPU buffer and fill the
  // physical texture. Sentinels would become visible if the source was overread.
  w2c_host_texture_create(nullptr, 10, 2, 1, 1);
  memset(memory + 1024, 0xee, 32);
  const u8 target_texels[] = {0, 0, 255, 255, 255, 0, 0, 255};
  memcpy(memory + 1024, target_texels, sizeof target_texels);
  w2c_host_texture_upload(nullptr, 10, 1024);
  w2c_host_set_render_target(nullptr, 10);
  u8 uploaded[32];
  glReadPixels(0, 0, 4, 2, GL_RGBA, GL_UNSIGNED_BYTE, uploaded);
  for (int i = 0; i < 8; ++i) {
    assert(uploaded[i * 4] == (i % 4 < 2 ? 255 : 0));
    assert(uploaded[i * 4 + 2] == (i % 4 < 2 ? 0 : 255));
    assert(uploaded[i * 4 + 3] == 255);
  }
  w2c_host_set_render_target(nullptr, 0);

  // Textured draws sample at output density, with the original stage filters.
  w2c_host_texture_create(nullptr, 9, 2, 1, 0);
  const u8 texels[] = {0, 0, 255, 255, 255, 0, 0, 255}; // BGRA: red, blue
  memcpy(memory + 1024, texels, sizeof texels);
  w2c_host_texture_upload(nullptr, 9, 1024);
  w2c_host_set_texture(nullptr, 0, 9);
  renderer_resize(2048, 1536);
  w2c_host_clear(nullptr, 0);
  rectangle(100, 100, 101, 101, 0xffffffff);
  pixels = renderer_capture(width, height);
  size_t first_texel = ((size_t)200 * width + 200) * 4;
  assert(pixels[first_texel] == 255 && pixels[first_texel + 2] == 0);
  assert(pixels[first_texel + 4] == 0 && pixels[first_texel + 6] == 255);
  w2c_host_set_texture(nullptr, 0, 0);

  // Capture, pause, save an anchor, resize, restore the anchor and resume.
  renderer_resize(1600, 1200);
  w2c_host_clear(nullptr, 0xff204080);
  w2c_host_frame_hold(nullptr, 1);
  w2c_host_frame_hold(nullptr, 3);
  glColorMask(GL_FALSE, GL_FALSE, GL_FALSE, GL_FALSE);
  renderer_resize(2560, 1440);
  w2c_host_frame_hold(nullptr, 4);
  w2c_host_frame_hold(nullptr, 0);
  assert(held.width == 1600 && anchor.width == 1600);
  pixels = renderer_capture(width, height);
  assert(width == 1920 && height == 1440);
  for (size_t i = 0; i < pixels.size(); i += 4) {
    assert(pixels[i] == 0x20 && pixels[i + 1] == 0x40 && pixels[i + 2] == 0x80);
    assert(pixels[i + 3] == 255);
  }
  rectangle(0, 0, 1024, 768, 0x00ff0000);
  pixels = renderer_capture(width, height);
  assert(pixels[0] == 255 && pixels[3] == 255); // X8 alpha survived restoration.
  w2c_host_frame_hold(nullptr, 1);
  assert(held.width == 1920);
  renderer_resize(800, 600);
  w2c_host_frame_hold(nullptr, 0);
  pixels = renderer_capture(width, height);
  assert(width == 800 && height == 600 && pixels[0] == 255 && pixels[3] == 255);
  renderer_resize(0, 0);
  assert(!renderer_viewport(0, 0).width && textures[0].width == 800);
  w2c_host_frame_hold(nullptr, 5);
  assert(!anchor.texture);

  // The top-left input rectangle and GL's bottom-left viewport agree even
  // when letterboxing leaves an odd number of unused physical rows.
  int drawable_w, drawable_h;
  SDL_GetWindowSizeInPixels(window, &drawable_w, &drawable_h);
  int present_w = drawable_w - 1, present_h = drawable_h;
  renderer_resize(present_w, present_h);
  Viewport v = renderer_viewport(present_w, present_h);
  w2c_host_clear(nullptr, 0xffff0000);
  rectangle(0, 384, 1024, 768, 0xff0000ff);
  renderer_present(present_w, present_h);
  glGetIntegerv(GL_VIEWPORT, viewport);
  assert(viewport[0] == v.x && viewport[1] == present_h - v.y - v.height);
  assert(viewport[2] == v.width && viewport[3] == v.height);
  std::vector<u8> screen((size_t)present_w * present_h * 4);
  glReadPixels(0, 0, present_w, present_h, GL_RGBA, GL_UNSIGNED_BYTE, screen.data());
  for (int y = 0; y < present_h; ++y) {
    bool inside = present_h - 1 - y >= v.y && present_h - 1 - y < v.y + v.height;
    int top_y = present_h - 1 - y - v.y;
    bool red = inside && top_y + .5f < v.height * .5f;
    size_t i = ((size_t)y * present_w + present_w / 2) * 4;
    assert(screen[i] == (red ? 255 : 0));
    assert(screen[i + 2] == (inside && !red ? 255 : 0));
  }
  renderer_resume();
  // Presentation still applies the gamma ramp, while captures stay pre-gamma.
  w2c_host_clear(nullptr, 0xff204080);
  for (int i = 0; i < 256; ++i) {
    unsigned short value = (unsigned short)((255 - i) * 257);
    memcpy(memory + i * 2, &value, sizeof value);
  }
  w2c_host_gamma_ramp(nullptr, 0, 0, 0);
  renderer_present(present_w, present_h);
  u8 center[4];
  glReadPixels(present_w / 2, present_h / 2, 1, 1, GL_RGBA, GL_UNSIGNED_BYTE, center);
  assert(center[0] == 0xdf && center[1] == 0xbf && center[2] == 0x7f);
  renderer_resume();
  assert(glGetError() == GL_NO_ERROR);
  puts("renderer: native density, logical projection/input, terrain, holds, anchors, alpha and presentation passed");
  SDL_GL_DestroyContext(context);
  SDL_DestroyWindow(window);
  SDL_Quit();
}
