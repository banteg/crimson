// Exercise the production renderer on a real GL context without game assets.
#include <SDL3/SDL.h>
#include <assert.h>
#include <stdlib.h>
#include <algorithm>
#include <string>
#include "../client/renderer.cpp"
#include "../client/thickness.cpp"

alignas(16) u8 memory[1024 * 1024];
u8 *client_memory() { return memory; }
float render_size = 2;
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

// Minimal bridge for the production full-screen helpers. grim_draw_quad takes
// raw D3D coordinates, unlike rectangle(), which supplies corrected edges, and
// Grim's corner UVs, clockwise from the top left.
struct IDirect3DDevice8 {
  void SetTexture(int stage, int id) { w2c_host_set_texture(nullptr, stage, id); }
  void SetTextureStageState(int stage, int state, int value) {
    w2c_host_texture_stage_state(nullptr, stage, state, value);
  }
} fullscreen_device;
IDirect3DDevice8 *grim_d3d_device = &fullscreen_device;
unsigned int grim_backbuffer_width = 1024, grim_backbuffer_height = 768;
enum { D3DTSS_COLOROP = TSS_COLOROP, D3DTSS_ALPHAOP = TSS_ALPHAOP,
       D3DTOP_SELECTARG2 = 3, D3DTOP_MODULATE = 4 };
struct IGrim2D_cpp {
  u32 color = 0xffffffff;
  void grim_set_rotation(float angle) { assert(angle == 0); }
  void grim_begin_batch() {}
  void grim_end_batch() {}
  void grim_set_color(float r, float g, float b, float a) {
    color = (u32)(a * 255) << 24 | (u32)(r * 255) << 16 | (u32)(g * 255) << 8 | (u32)(b * 255);
  }
  void grim_draw_quad(float x, float y, float w, float h);
  void grim_draw_fullscreen_quad(int);
  void grim_draw_fullscreen_color(float, float, float, float);
};
#include "fullscreen.inc"
GrimUV grim_uv_u0[4];
void IGrim2D_cpp::grim_draw_quad(float x, float y, float w, float h) {
  const GrimUV *uv = grim_uv_u0;
  Vertex vertices[] = {{x, y, 0, 1, color, uv[0].u, uv[0].v},
                       {x + w, y, 0, 1, color, uv[1].u, uv[1].v},
                       {x, y + h, 0, 1, color, uv[3].u, uv[3].v},
                       {x + w, y + h, 0, 1, color, uv[2].u, uv[2].v}};
  memcpy(memory, vertices, sizeof vertices);
  w2c_host_draw(nullptr, 5, 0, 4, 0, 2);
}

// Opaque black and white stripes, one texel per logical pixel along one axis.
void stripes(u32 id, int width, int height) {
  w2c_host_texture_create(nullptr, id, width, height, 0);
  for (int i = 0; i < width * height; ++i) {
    memset(memory + 1024 + i * 4, i % 2 ? 255 : 0, 3);
    memory[1024 + i * 4 + 3] = 255;
  }
  w2c_host_texture_upload(nullptr, id, 1024);
}

// Draw over a magenta previous frame, visible through any gap.
template <class Draw> std::vector<u8> over_stale(Draw draw) {
  w2c_host_clear(nullptr, 0xffff00ff);
  draw();
  int width, height;
  return renderer_capture(width, height);
}
bool stale(const u8 *pixel) { return pixel[0] == 255 && pixel[1] == 0 && pixel[2] == 255; }

void check_fullscreen(int width, int height) {
  renderer_resize(width, height);
  Viewport v = renderer_viewport(width, height);
  auto fail = [&](const char *what, size_t i) {
    fprintf(stderr, "full-screen %s at %zu,%zu in %dx%d\n", what, i / 4 % v.width, i / 4 / v.width,
            v.width, v.height);
    abort();
  };
  IGrim2D_cpp grim;
  auto pixels = over_stale([&] { grim.grim_draw_fullscreen_color(0, 0, 0, 1); });
  for (size_t i = 0; i < pixels.size(); i += 4)
    if (pixels[i] || pixels[i + 1] || pixels[i + 2] || pixels[i + 3] != 255)
      fail("color gap", i);
  w2c_host_texture_stage_state(nullptr, 0, TSS_ALPHAOP, 3);

  // A textured quad covers every pixel too, and samples each where the
  // original's quad from (0, 0) does: a half-pixel shift turns its grey
  // texel boundaries into stripes. Offset UVs, as terrain's camera sets them.
  grim.grim_set_color(1, 1, 1, 1);
  w2c_host_texture_stage_state(nullptr, 0, TSS_MINFILTER, 2);
  w2c_host_texture_stage_state(nullptr, 0, TSS_MAGFILTER, 2);
  for (u32 texture : {98u, 99u}) {
    w2c_host_set_texture(nullptr, 0, texture);
    const GrimUV uv[4] = {{.25f, .5f}, {1.25f, .5f}, {1.25f, 1.5f}, {.25f, 1.5f}};
    memcpy(grim_uv_u0, uv, sizeof uv);
    auto reference = over_stale([&] {
      grim.grim_draw_quad(0, 0, (float)grim_backbuffer_width, (float)grim_backbuffer_height);
    });
    pixels = over_stale([&] { grim.grim_draw_fullscreen_quad(0); });
    assert(!memcmp(grim_uv_u0, uv, sizeof uv)); // The caller's UVs remain.
    bool sampled = false;
    for (size_t i = 0; i < pixels.size(); i += 4) {
      if (stale(&pixels[i]) || pixels[i + 3] != 255)
        fail("texture gap", i);
      if (stale(&reference[i]))
        continue;
      sampled |= reference[i] < 192;
      for (int c = 0; c < 3; ++c)
        if (abs(pixels[i + c] - reference[i + c]) > 2)
          fail("texture sampling moved", i);
    }
    assert(sampled);
  }
  w2c_host_set_texture(nullptr, 0, 0);
  w2c_host_texture_stage_state(nullptr, 0, TSS_MINFILTER, 1);
  w2c_host_texture_stage_state(nullptr, 0, TSS_MAGFILTER, 1);
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

#ifdef RENDERER_BENCHMARK
void benchmark(bool terrain) {
  // Three production-sized terrain batches, same geometry/data in all modes.
  w2c_host_texture_create(nullptr, 101, 256, 256, 0);
  for (int y = 0; y < 256; ++y)
    for (int x = 0; x < 256; ++x) {
      size_t i = ((size_t)y * 256 + x) * 4;
      float r = hypotf((x - 127.5f) / 128, (y - 127.5f) / 128);
      memory[i] = (x * 17 + y * 13) & 255;
      memory[i + 1] = (x * 3 + y * 7) & 255;
      memory[i + 2] = 128;
      memory[i + 3] = (u8)(255 * fmaxf(0, 1 - r));
    }
  w2c_host_texture_upload(nullptr, 101, 0);
  w2c_host_texture_create(nullptr, 102, 1024, 1024, 3);
  w2c_host_set_render_target(nullptr, 102);
  w2c_host_set_texture(nullptr, 0, 101);
  w2c_host_set_texture(nullptr, 1, 0);
  w2c_host_texture_stage_state(nullptr, 0, TSS_MINFILTER, 2);
  w2c_host_texture_stage_state(nullptr, 0, TSS_MAGFILTER, 2);
  w2c_host_texture_stage_state(nullptr, 0, TSS_TERRAIN_ART, terrain && RENDERER_BENCHMARK == 2);
  w2c_host_texture_stage_state(nullptr, 0, TSS_COLOROP, 4);
  w2c_host_texture_stage_state(nullptr, 0, TSS_ALPHAOP, 4);
  w2c_host_texture_stage_state(nullptr, 0, TSS_COLORARG1, 2);
  w2c_host_texture_stage_state(nullptr, 0, TSS_COLORARG2, 1);
  w2c_host_texture_stage_state(nullptr, 0, TSS_ALPHAARG1, 2);
  w2c_host_texture_stage_state(nullptr, 0, TSS_ALPHAARG2, 1);
  w2c_host_texture_stage_state(nullptr, 0, TSS_ADDRESSU, 1);
  w2c_host_texture_stage_state(nullptr, 0, TSS_ADDRESSV, 1);
  w2c_host_texture_stage_state(nullptr, 1, TSS_COLOROP, 1);
  w2c_host_render_state(nullptr, RS_CULLMODE, 1);
  w2c_host_render_state(nullptr, RS_ALPHABLENDENABLE, 1);
  w2c_host_render_state(nullptr, RS_SRCBLEND, 5);
  w2c_host_render_state(nullptr, RS_DESTBLEND, 6);
  w2c_host_render_state(nullptr, RS_ALPHATESTENABLE, 1);
  w2c_host_render_state(nullptr, RS_ALPHAFUNC, 7);
  w2c_host_render_state(nullptr, RS_ALPHAREF, 4);
  w2c_host_render_state(nullptr, RS_COLORWRITEENABLE, 7);
  std::vector<Vertex> batches[3];
  unsigned seed = 0xc0ffee;
  auto random = [&]() { seed = seed * 1664525 + 1013904223; return seed; };
  int counts[] = {terrain ? 1600 : 400, terrain ? 70 : 80, terrain ? 30 : 20};
  float size = terrain ? 128.f : 48.f;
  for (int b = 0; b < 3; ++b)
    for (int i = 0; i < counts[b]; ++i) {
      float angle = (random() % 314) * .01f, x = (int)(random() % 1152) - 64.f,
            y = (int)(random() % 1152) - 64.f, c = cosf(angle), s = sinf(angle);
      for (int k : {0, 1, 2, 2, 1, 3}) {
        float u = k & 1, v = k >> 1, dx = (u - .5f) * size, dy = (v - .5f) * size;
        batches[b].push_back({x + 64 + dx*c - dy*s - .5f, y + 64 + dx*s + dy*c - .5f,
                              0, 1, b == 2 ? 0x99b2b2b2u : 0xe6b2b2b2u, u, v});
      }
    }
  std::vector<double> samples;
  int repetitions = terrain ? 1 : 16; // Average small frames across browser timer quantization.
  for (int iteration = 0; iteration < 24; ++iteration) {
    glFinish();
    Uint64 start = SDL_GetPerformanceCounter();
    u8 pixel[4];
    for (int repeat = 0; repeat < repetitions; ++repeat) {
      w2c_host_clear(nullptr, 0xff3f3819);
      for (auto &vertices : batches) {
        memcpy(memory, vertices.data(), vertices.size() * sizeof(Vertex));
        w2c_host_draw(nullptr, 4, 0, (u32)vertices.size(), 0, (u32)vertices.size() / 3);
      }
      glReadPixels(1024, 1024, 1, 1, GL_RGBA, GL_UNSIGNED_BYTE, pixel);
      glFinish();
    }
    double ms = (SDL_GetPerformanceCounter() - start) * 1000.0 / SDL_GetPerformanceFrequency() / repetitions;
    assert(pixel[3] == 255 && glGetError() == GL_NO_ERROR);
    if (iteration >= 4) samples.push_back(ms);
  }
  std::sort(samples.begin(), samples.end());
  printf("BENCHMARK {\"workload\":\"%s\",\"mode\":%d,\"samples\":20,\"quads\":%d,\"size\":2048,\"median_ms\":%.4f,\"p95_ms\":%.4f}\n",
         terrain ? "terrain" : "sprites", RENDERER_BENCHMARK, terrain ? 1700 : 500,
         (samples[9]+samples[10])/2, samples[18]);
}
#endif

// The back buffer's red channel at a logical pixel, as stored.
struct Pixel {
  float r, g, b, a;
};
Pixel back_pixel(int x, int y) {
  Target &back = textures[0];
  Pixel pixel;
  glBindFramebuffer(GL_FRAMEBUFFER, back.framebuffer);
  glReadPixels(x * back.width / back.logical_width, y * back.height / back.logical_height, 1, 1, GL_RGBA, GL_FLOAT,
               &pixel);
  bind_target();
  return pixel;
}
float back_red(int x, int y) { return back_pixel(x, y).r; }

// RTX: an additive stack of three whites draws past white in the world's HDR
// target, whose tonemap rolls it off below white without EDR headroom and past
// white with it, while what stays under the shoulder's knee lands unchanged.
// Classic saturates each draw on its 8-bit back buffer.
void check_rtx() {
#ifdef __EMSCRIPTEN__
  assert(!renderer_set_rtx(true));
#else
  renderer_resize(2048, 1536);
  w2c_host_set_texture(nullptr, 0, 0);
  w2c_host_texture_stage_state(nullptr, 0, TSS_COLOROP, 3);
  w2c_host_texture_stage_state(nullptr, 0, TSS_COLORARG2, 0);
  w2c_host_render_state(nullptr, RS_ALPHABLENDENABLE, 1);
  w2c_host_render_state(nullptr, RS_SRCBLEND, 2);
  w2c_host_render_state(nullptr, RS_DESTBLEND, 2);
  auto world = [] {
    w2c_host_clear(nullptr, 0xff000000);
    w2c_host_render_pass(nullptr, 1);
    for (int i = 0; i < 3; ++i)
      rectangle(0, 0, 512, 768, 0xffffffff);
    rectangle(512, 0, 1024, 768, 0xff808080);
    w2c_host_render_pass(nullptr, 2);
  };
  assert(renderer_set_rtx(true) && (textures[0].flags & TARGET_HALF_FLOAT));
  // A beam head is one stamp: the glow texel's peak at its center, nothing past its radius.
  // A 256-pixel body (a streak's longest) fades in from its tail and is
  // symmetric about its axis, which sits on physical row 768 (Direct3D's
  // half-pixel shift included).
  auto beam = [](std::initializer_list<float> corners, float length, float step) {
    memcpy(memory, corners.begin(), corners.size() * sizeof(float));
    w2c_host_beam(nullptr, 0, length, step, 0xffffffff);
  };
  w2c_host_clear(nullptr, 0xff000000);
  beam({495.75f, 367.75f, -1, -1, 495.75f, 399.75f, -1, 1, 527.75f, 399.75f, 1, 1, 527.75f, 367.75f, 1, -1}, -1, 0);
  assert(fabsf(back_red(512, 384) - 0.863f) < 1e-2f && back_red(512, 399) < 1e-3f);
  w2c_host_clear(nullptr, 0xff000000);
  float length = 256 / 16.0f;
  beam({184, 367.75f, -1, -1, 184, 399.75f, -1, 1, 472, 399.75f, length + 1, 1, 472, 367.75f, length + 1, -1}, length,
       3.1f / 16);
  assert(back_red(210, 384) < back_red(330, 384) && back_red(330, 384) < back_red(450, 384));
  assert(fabsf(back_red(330, 378) - back_red(330, 390)) < 1e-3f && back_red(330, 380) > 0);
  assert(back_red(330, 410) == 0);
  // The same effect.frag as Python: radial glow/aura/shell, HDR plasma,
  // and capped/cut ion arcs. Uniform arrays and blend state reach real GL.
  auto effect = [&](int kind, const float *params, unsigned color, float x0, float x1, float y0, float y1,
                    float u0, float u1, float v0, float v1) {
    const float c[16] = {x0,y0,u0,v0, x0,y1,u0,v1, x1,y1,u1,v1, x1,y0,u1,v0};
    memcpy(memory, c, sizeof c);
    memcpy(memory+128, params, 48);
    w2c_host_effect(nullptr, 0, kind, 128, color);
  };
  w2c_host_render_state(nullptr, RS_SRCBLEND, 5);
  const float empty[12] = {};
  for (int kind = 0; kind < 3; ++kind) {
    w2c_host_clear(nullptr, 0xff000000);
    effect(kind, empty, 0xffffffff, 495.75f,527.75f,367.75f,399.75f,-1,1,-1,1);
    if (kind < 2) assert(back_red(512,384) > .7f);
    else assert(back_red(512,384) == 0 && back_red(526,384) > .1f);
    assert(back_red(492,384) == 0);
    w2c_host_clear(nullptr, 0xff000000);
    effect(kind, empty, 0x01ffffff, 495.75f,527.75f,367.75f,399.75f,-1,1,-1,1);
    assert(back_red(512,384) == 0 && back_red(526,384) == 0);
  }
  // One device-vertex batch retains different sprite tints exactly, including
  // byte color swizzling and alpha, through the actual GPU vertex layout.
  for (int kind = 0; kind < 3; ++kind) {
    w2c_host_clear(nullptr, 0xff000000);
    effect(kind, empty, 0xff408020, 495.75f, 527.75f, 367.75f, 399.75f, -1, 1,
           -1, 1);
    effect(kind, empty, 0x802040ff, 575.75f, 607.75f, 367.75f, 399.75f, -1, 1,
           -1, 1);
    int width, height;
    auto reference = renderer_capture(width, height);
    const float a[16] = {495.75f, 367.75f, -1, -1, 495.75f, 399.75f, -1, 1,
                         527.75f, 399.75f, 1,  1,  527.75f, 367.75f, 1,  -1};
    const float b[16] = {575.75f, 367.75f, -1, -1, 575.75f, 399.75f, -1, 1,
                         607.75f, 399.75f, 1,  1,  607.75f, 367.75f, 1,  -1};
    EffectVertex sprites[12];
    effect_quad(a, 0xff408020, sprites);
    effect_quad(b, 0x802040ff, sprites + 6);
    memcpy(memory + 4096, sprites, sizeof sprites);
    w2c_host_clear(nullptr, 0xff000000);
    w2c_host_effect_sprites(nullptr, 4096, kind, 12);
    assert(renderer_capture(width, height) == reference);
  }
  w2c_host_clear(nullptr, 0xff000000);
  const float plasma[12] = {8, 0, 0, 27, 1.5f, .4f, 0, 0, 1, 0, 0, 0};
  effect(3,plasma,0xffffffff,477.75f,521.75f,375.75f,391.75f,-34,10,-8,8);
  assert(back_red(500,384) > 1.f && back_red(500,400) == 0);
  // An ion arc's length in strip scales rides on its vertices, negative where
  // its strips end in the native cut.
  for (float length : {48.f, -48.f}) {
    const float corners[16] = {471.75f, 367.75f, -16, -16, 471.75f, 399.75f, -16, 16,
                               551.75f, 399.75f, 64,  16,  551.75f, 367.75f, 64,  -16};
    EffectVertex arc[6];
    effect_quad(corners, 0xff8099ff, arc);
    for (EffectVertex &v : arc)
      v.z = length;
    memcpy(memory + 4096, arc, sizeof arc);
    w2c_host_clear(nullptr, 0xff000000);
    w2c_host_effect_sprites(nullptr, 4096, 4, 6);
    assert((length > 0 ? back_red(485, 384) > .01f : back_red(485, 384) == 0) && back_red(510, 384) > .1f);
  }
  // Lit batches: creature bodies keep a 0.6 linear ambient fill without lights
  // and brighten under one; players without lights keep the device's shading.
  w2c_host_render_state(nullptr, RS_ALPHABLENDENABLE, 0);
  w2c_host_texture_create(nullptr, 300, 64, 64, 0);
  memset(memory + 4096, 255, 64 * 64 * 4);
  w2c_host_texture_upload(nullptr, 300, 4096);
  w2c_host_set_texture(nullptr, 0, 300);
  w2c_host_texture_stage_state(nullptr, 0, TSS_COLOROP, 4);
  w2c_host_texture_stage_state(nullptr, 0, TSS_COLORARG1, 2);
  w2c_host_texture_stage_state(nullptr, 0, TSS_COLORARG2, 0);
  renderer_set_headroom(1);
  // A frame's scene: no camera offset, the clock at zero, a 1024-unit terrain,
  // and up to one light (its first 16 floats; no tail, broad fill or beam).
  auto scene = [](std::initializer_list<float> light, int count) {
    const float view[7] = {0, 0, 0, 1024, 1024, 4, 3};
    float packed[RTX_LIGHT_FLOATS] = {};
    std::copy(light.begin(), light.end(), packed);
    memcpy(memory + 32768, view, sizeof view);
    memcpy(memory + 32832, packed, sizeof packed);
    w2c_host_scene(nullptr, 32768, 32832, count);
  };
  auto lit = [&](int pass, int lights) {
    scene({512, 384, 200, 18, 1, 1, 1, 0, 0, 0, 0, 0, 1, 0, 200, 3}, lights);
    w2c_host_render_pass(nullptr, HOST_PASS_WORLD_BEGIN);
    w2c_host_render_pass(nullptr, pass);
    rectangle(0, 0, 1024, 768, 0xffffffff);
    w2c_host_render_pass(nullptr, HOST_PASS_SPRITES);
    w2c_host_render_pass(nullptr, HOST_PASS_WORLD_END);
    return back_red(512, 384);
  };
  float device = lit(HOST_PASS_SPRITES, 0), ambient = lit(HOST_PASS_CREATURES, 0);
  assert(fabsf(ambient - powf(0.6f, 1 / 2.2f)) < 2e-3f);
  assert(lit(HOST_PASS_CREATURES, 1) > ambient + 0.05f);
  assert(lit(HOST_PASS_PLAYERS, 0) == device && lit(HOST_PASS_PLAYERS, 1) > device);
  // Bonuses: a shell is black glass, dim but for a fixed key highlight, whose
  // clear coat mirrors a light above it; an emblem without lights keeps the
  // device's colors. The quad spans the
  // atlas's 4x4 grid, so its cell (1, 1) centers at (384, 288).
  auto bonus = [&](int emblem, int lights) {
    scene({384, 288, 200, 18, 1, 1, 1, 0, 0, 0, 0, 0, 1, 1, 200, 3}, lights);
    w2c_host_render_pass(nullptr, HOST_PASS_WORLD_BEGIN);
    w2c_host_bonus(nullptr, emblem, 4, 4, 384, 288);
    rectangle(0, 0, 1024, 768, 0xffffffff);
    w2c_host_render_pass(nullptr, HOST_PASS_SPRITES);
    w2c_host_render_pass(nullptr, HOST_PASS_WORLD_END);
    return back_red(384, 288);
  };
  float shell = bonus(0, 0);
  assert(shell < 0.3f && bonus(0, 1) > shell + 0.5f);
  assert(fabsf(bonus(1, 0) - device) < 2e-3f);
  // A body between the light and a creature-sized batch (one grid cell holding
  // it) shades it from the quad's corners, unless the shadows setting is off.
  auto occluded = [&](float shadows) {
    const float grid[6] = {0, 0, 1, 1, 2048, shadows};
    const float values[20] = {4, 1, 0, 0,                     // cell 0: its list at texel 4, one body
                              400, 384, 16, 64,                // body: center, height * 0.4, bound
                              1 / 60.f, 1 / 60.f, 1 / 24.f, 1e20f, // inverse radii, owner x
                              1, 0, 1, 1e20f,                  // rotation, opacity, owner y
                              1, 0, 0, 0};                     // the cell's list: the body at texel 1
    memcpy(memory + 33024, grid, sizeof grid);
    memcpy(memory + 33152, values, sizeof values);
    w2c_host_occlusion(nullptr, 33024, 33152, 20);
    scene({200, 384, 600, 18, 1, 1, 1, 0, 0, 0, 0, 0, 1, 0, 600, 3}, 1);
    w2c_host_render_pass(nullptr, HOST_PASS_WORLD_BEGIN);
    w2c_host_render_pass(nullptr, HOST_PASS_CREATURES);
    rectangle(568, 352, 632, 416, 0xffffffff);
    w2c_host_render_pass(nullptr, HOST_PASS_SPRITES);
    w2c_host_render_pass(nullptr, HOST_PASS_WORLD_END);
    return back_red(600, 384);
  };
  float open = occluded(0), shaded = occluded(1);
  assert(shaded < open - 0.02f);
  const float none[6] = {0, 0, 0, 0, 64, 1};
  memcpy(memory + 33024, none, sizeof none);
  w2c_host_occlusion(nullptr, 33024, 0, 0);
  // The ground: a gray terrain target drawn into the world through its
  // companions, a world unit a pixel. Blood baked into it soaks the ground dark
  // red, although the terrain itself took the decal white; brass mirrors a
  // light the bare ground does not; a clear drops the companions with what
  // they held.
  w2c_host_texture_create(nullptr, 400, 1024, 1024, 1);
  auto terrain = [] {
    w2c_host_set_render_target(nullptr, 400);
    w2c_host_clear(nullptr, 0xff808080);
    w2c_host_set_render_target(nullptr, 0);
  };
  auto decal = [](int kind, float x, float y) {
    w2c_host_set_render_target(nullptr, 400);
    w2c_host_render_state(nullptr, RS_ALPHABLENDENABLE, 1);
    w2c_host_render_state(nullptr, RS_SRCBLEND, 5);
    w2c_host_render_state(nullptr, RS_DESTBLEND, 6);
    w2c_host_ground(nullptr, kind, 0);
    rectangle(x - 48, y - 48, x + 48, y + 48, 0xc8ffffff);
    w2c_host_ground(nullptr, (u32)HOST_GROUND_END, 0);
    w2c_host_render_state(nullptr, RS_ALPHABLENDENABLE, 0);
    w2c_host_render_state(nullptr, RS_SRCBLEND, 2);
    w2c_host_render_state(nullptr, RS_DESTBLEND, 2);
    w2c_host_set_render_target(nullptr, 0);
  };
  auto ground = [&](std::initializer_list<float> light, int count, int x, int y) {
    scene(light, count);
    w2c_host_render_pass(nullptr, HOST_PASS_WORLD_BEGIN);
    w2c_host_render_pass(nullptr, HOST_PASS_GROUND);
    w2c_host_set_texture(nullptr, 0, 400);
    rectangle(0, 0, 1024, 1024, 0xffffffff);
    w2c_host_set_texture(nullptr, 0, 300);
    w2c_host_render_pass(nullptr, HOST_PASS_SPRITES);
    w2c_host_render_pass(nullptr, HOST_PASS_WORLD_END);
    return back_pixel(x, y);
  };
  terrain();
  decal(HOST_GROUND_BLOOD, 200, 200);
  decal(HOST_GROUND_BRASS, 600, 400);
  Pixel bare = ground({}, 0, 400, 200), blood = ground({}, 0, 200, 200);
  assert(fabsf(bare.r - bare.g) < 0.02f && bare.r > 0.25f);
  assert(blood.g < bare.g * 0.5f && blood.r > blood.g * 2);
  // A broad mirror source above (the reflection lands below its emitter).
  const std::initializer_list<float> mirror = {600, 390, 200, 18, 1, 1, 1, 0, 0, 0, 0, 0, 0, 1, 200, 40};
  assert(ground(mirror, 1, 600, 400).r > ground({}, 0, 600, 400).r + 0.1f);
  assert(fabsf(ground(mirror, 1, 400, 400).r - ground({}, 0, 400, 400).r) < 1e-3f);
  // Three minutes on, a bake's stamp rebases the surface's wetness, and the
  // terrain stays bound: the decal after it still lands in the terrain.
  w2c_host_set_render_target(nullptr, 400);
  w2c_host_ground(nullptr, HOST_GROUND_BLOOD, 200);
  rectangle(100, 700, 150, 750, 0xc8ffffff);
  w2c_host_ground(nullptr, HOST_GROUND_DECAL, 200);
  rectangle(800, 100, 1000, 900, 0xffff0000);
  w2c_host_ground(nullptr, (u32)HOST_GROUND_END, 0);
  w2c_host_set_render_target(nullptr, 400);
  u8 stamped[4];
  glReadPixels(1800, 1000, 1, 1, GL_RGBA, GL_UNSIGNED_BYTE, stamped);
  assert(stamped[0] == 255 && stamped[1] == 0 && stamped[2] == 0);
  w2c_host_set_render_target(nullptr, 0);
  terrain();
  Pixel cleared = ground({}, 0, 200, 200);
  assert(fabsf(cleared.g - bare.g) < 1e-3f);
  w2c_host_texture_release(nullptr, 400);
  // Monster Vision's heat trails: a footprint warms the ground under it as faint
  // ironbow heat and nothing past it; the trail fades by its half-life on the
  // run's clock and starts over when the clock runs back.
  auto trail = [](float seconds, int count, int x, int y) {
    const float view[7] = {0, 0, seconds, 1024, 1024, 4, 3};
    const float footprint[4] = {700, 300, 20, 1};
    memcpy(memory + 32768, view, sizeof view);
    memcpy(memory + 33500, footprint, sizeof footprint);
    w2c_host_scene(nullptr, 32768, 32832, 0);
    w2c_host_heat(nullptr, 33500, count);
    w2c_host_clear(nullptr, 0xff000000);
    w2c_host_render_pass(nullptr, HOST_PASS_WORLD_BEGIN);
    w2c_host_heat_trails(nullptr, 1);
    w2c_host_render_pass(nullptr, HOST_PASS_WORLD_END);
    return back_pixel(x, y);
  };
  Pixel hot = trail(10, 1, 700, 300);
  assert(hot.r > 0.2f && hot.r > hot.g * 2 && trail(10, 1, 700, 360).r < 1e-3f);
  float faded = trail(10.9f, 0, 700, 300).r;
  assert(faded < hot.r * 0.8f && faded > 0.01f);
  assert(trail(5, 0, 700, 300).r < 1e-3f);
  // Monster Vision's heat bodies: a creature batch drawn again in the ironbow
  // ramp, red its warmth and alpha its opacity, whatever the sprite's own tint.
  auto heat_body = [](u32 color) {
    w2c_host_clear(nullptr, 0xff000000);
    w2c_host_render_pass(nullptr, HOST_PASS_WORLD_BEGIN);
    w2c_host_render_state(nullptr, RS_ALPHABLENDENABLE, 1);
    w2c_host_render_state(nullptr, RS_SRCBLEND, 5);
    w2c_host_render_state(nullptr, RS_DESTBLEND, 6);
    w2c_host_set_texture(nullptr, 0, 300);
    w2c_host_render_pass(nullptr, HOST_PASS_HEAT);
    rectangle(400, 300, 464, 364, color);
    w2c_host_render_pass(nullptr, HOST_PASS_SPRITES);
    w2c_host_render_state(nullptr, RS_SRCBLEND, 2);
    w2c_host_render_state(nullptr, RS_DESTBLEND, 2);
    w2c_host_render_state(nullptr, RS_ALPHABLENDENABLE, 0);
    w2c_host_render_pass(nullptr, HOST_PASS_WORLD_END);
    return back_pixel(436, 336); // an atlas cell's middle
  };
  Pixel warm = heat_body(0xe0ff0000), cold = heat_body(0xe0000000), unseen = heat_body(0x00ff0000);
  assert(warm.r > 0.5f && warm.r > warm.b && cold.r < warm.r * 0.5f && unseen.r < 1e-3f);
  // An ion contact's glow adds its hue to the ground as a disc, brightest at its
  // center and nothing at the quad's corners; glows add.
  auto glow = [](int quads, int x, int y) {
    w2c_host_clear(nullptr, 0xff000000);
    w2c_host_render_pass(nullptr, HOST_PASS_WORLD_BEGIN);
    w2c_host_render_state(nullptr, RS_ALPHABLENDENABLE, 1);
    w2c_host_render_pass(nullptr, HOST_PASS_GLOW);
    for (int i = 0; i < quads; ++i)
      rectangle(400, 300, 520, 420, 0x406080ff);
    w2c_host_render_pass(nullptr, HOST_PASS_SPRITES);
    w2c_host_render_state(nullptr, RS_ALPHABLENDENABLE, 0);
    w2c_host_render_pass(nullptr, HOST_PASS_WORLD_END);
    return back_pixel(x, y);
  };
  Pixel contact = glow(1, 460, 360), stacked = glow(2, 460, 360);
  assert(contact.b > 0.1f && contact.b > contact.g && contact.g > contact.r);
  assert(stacked.b > contact.b * 1.2f && glow(1, 402, 302).b < 1e-3f);
  // A pressure front brightens the world along its crest, darkens it just
  // inside, and leaves the world past it alone.
  auto front = [](int count, int x, int y) {
    const float fronts[4] = {312, 384, 200, 1};
    memcpy(memory + 33600, fronts, sizeof fronts);
    w2c_host_pressure(nullptr, 33600, count);
    w2c_host_clear(nullptr, 0xff000000);
    w2c_host_render_pass(nullptr, HOST_PASS_WORLD_BEGIN);
    rectangle(0, 0, 1024, 768, 0xff606060);
    w2c_host_render_pass(nullptr, HOST_PASS_WORLD_END);
    w2c_host_pressure(nullptr, 33600, 0);
    return back_red(x, y);
  };
  float flat = front(0, 512, 384);
  assert(front(1, 512, 384) > flat * 1.08f && front(1, 504, 384) < flat && fabsf(front(1, 800, 384) - flat) < 1e-3f);
  // Fluid smoke: a splat stepped once draws as a translucent gray cloud over a
  // black world, brighter under a light above it; a reset clears it.
  auto smoke = [](std::initializer_list<float> commands, int lights) {
    std::copy(commands.begin(), commands.end(), (float *)(memory + 40000));
    w2c_host_clear(nullptr, 0xff000000);
    w2c_host_render_pass(nullptr, HOST_PASS_WORLD_BEGIN);
    w2c_host_smoke(nullptr, 40000, (u32)commands.size());
    const float view[9] = {-128, -128, 1280, 1280, -128, -128, 1280, 1280, 1};
    const float light[SMOKE_LIGHT_FLOATS] = {534, 384, 30, 300, 1, 1, 1, 4, 0, 0, 0, 0, 1};
    memcpy(memory + 41000, view, sizeof view);
    memcpy(memory + 41100, light, sizeof light);
    w2c_host_smoke_draw(nullptr, 41000, 41100, lights, 0, 0);
    w2c_host_render_pass(nullptr, HOST_PASS_WORLD_END);
    return back_pixel(534, 384);
  };
  // An emission at (512, 384), 64 units across, its center a third of its size downstream.
  const float splat_center_u = (534 + 128) / 1280.0f, splat_center_v = (384 + 128) / 1280.0f;
  Pixel cloud = smoke({SMOKE_RESET, 320, 1280, 1280, 1 / 60.0f, 12,
                       SMOKE_SPLAT, splat_center_u - 0.125f, splat_center_v - 0.125f, 0.25f, 0.25f,
                       splat_center_u, splat_center_v, 64, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0,
                       SMOKE_PROJECT, SMOKE_TRANSPORT, 0.2f}, 0);
  assert(cloud.r > 0.1f && fabsf(cloud.r - cloud.b) < 0.1f);
  assert(smoke({}, 1).r > cloud.r + 0.05f);
  assert(smoke({SMOKE_RESET, 320, 1280, 1280, 1 / 60.0f, 12}, 0).r == 0);
  w2c_host_set_texture(nullptr, 0, 0);
  w2c_host_texture_release(nullptr, 300);
  w2c_host_texture_stage_state(nullptr, 0, TSS_COLOROP, 3);
  w2c_host_texture_stage_state(nullptr, 0, TSS_COLORARG2, 0);
  w2c_host_render_state(nullptr, RS_ALPHABLENDENABLE, 1);
  float limit = 0;
  for (float headroom : {1.0f, 4.0f}) {
    renderer_set_headroom(headroom);
    world();
    float highlight = back_red(100, 100), shadow = back_red(700, 100);
    assert(fabsf(shadow - 128 / 255.0f) < 1e-3f);
    assert(highlight > 0.85f && (headroom == 1 ? highlight <= 1 : highlight > 1 && highlight < powf(4, 1 / 2.2f)));
    limit = highlight;
  }
  // Past twice the game's resolution the world draws at twice it (rendersize)
  // and scales up as it tonemaps, while the back buffer keeps the display's
  // pixels for the HUD; 0 lifts the cap.
  int window_width = drawable_width, window_height = drawable_height;
  renderer_resize(3840, 2160);
  world();
  assert(textures[0].width == 2880 && hdr.width == 2048 && hdr.height == 1536);
  assert(fabsf(back_red(100, 100) - limit) < 1e-3f && fabsf(back_red(700, 100) - 128 / 255.0f) < 1e-3f);
  render_size = 0;
  world();
  assert(hdr.width == 2880 && hdr.height == 2160);
  render_size = 2;
  renderer_resize(window_width, window_height);
  assert(!renderer_set_rtx(false) && !(textures[0].flags & TARGET_HALF_FLOAT));
  assert(fabsf(back_red(100, 100) - 1) < 1e-3f && limit > 1); // the switch kept the image, clipped to 8 bits
  world();
  assert(back_red(100, 100) == 1 && fabsf(back_red(700, 100) - 128 / 255.0f) < 1e-3f);
  w2c_host_render_state(nullptr, RS_ALPHABLENDENABLE, 0);
  w2c_host_texture_stage_state(nullptr, 0, TSS_COLOROP, 4);
#endif
  puts("renderer: RTX world tonemaps highlights toward the EDR headroom, beams integrate their stamps, lit batches light, bodies shade them, bonus shells mirror lights, blood soaks and brass mirrors the ground, smoke scatters, Monster Vision shows heat and trails, ion contacts glow, pressure fronts ripple; classic stays 8-bit");
}


// Reusing indices and applied state must survive arbitrary indexed draws,
// helper passes, changing device arrays, and returning to the same shader.
void check_submission_reuse() {
  w2c_host_set_render_target(nullptr, 0);
  renderer_resize(128, 128);
  w2c_host_back_buffer(nullptr, 64, 64);
  w2c_host_set_texture(nullptr, 0, 0);
  w2c_host_set_texture(nullptr, 1, 0);
  w2c_host_render_state(nullptr, RS_CULLMODE, 1);
  w2c_host_render_state(nullptr, RS_ALPHABLENDENABLE, 0);
  w2c_host_render_state(nullptr, RS_ALPHATESTENABLE, 0);
  w2c_host_render_state(nullptr, RS_COLORWRITEENABLE, 15);
  w2c_host_texture_stage_state(nullptr, 0, TSS_COLOROP, 3);
  w2c_host_texture_stage_state(nullptr, 0, TSS_COLORARG2, 0);
  w2c_host_texture_stage_state(nullptr, 0, TSS_ALPHAOP, 3);
  w2c_host_texture_stage_state(nullptr, 0, TSS_ALPHAARG2, 0);
  w2c_host_texture_stage_state(nullptr, 1, TSS_COLOROP, 1);
  Vertex vertices[] = {{-.5f, -.5f, 0, 1, 0xffff0000, 0, 0}, {31.5f, -.5f, 0, 1, 0xffff0000, 1, 0},
                       {31.5f, 63.5f, 0, 1, 0xffff0000, 1, 1}, {-.5f, 63.5f, 0, 1, 0xffff0000, 0, 1},
                       {31.5f, -.5f, 0, 1, 0xff00ff00, 0, 0}, {63.5f, -.5f, 0, 1, 0xff00ff00, 1, 0},
                       {63.5f, 63.5f, 0, 1, 0xff00ff00, 1, 1}, {31.5f, 63.5f, 0, 1, 0xff00ff00, 0, 1}};
  const unsigned short quads[] = {0, 1, 2, 2, 3, 0, 4, 5, 6, 6, 7, 4};
  unsigned short reordered[] = {4, 5, 6, 6, 7, 4, 0, 1, 2, 2, 3, 0};
  auto draw = [&](const unsigned short *indices, u32 primitive = 4, u32 count = 4) {
    memcpy(memory, vertices, sizeof vertices);
    memcpy(memory + 4096, indices, (primitive == 4 ? count * 3 : count + 2) * sizeof *indices);
    w2c_host_clear(nullptr, 0xff000000);
    w2c_host_draw(nullptr, primitive, 0, 8, 4096, count);
    int width, height;
    return renderer_capture(width, height);
  };
  // These checks use an RGBA8 target. WebGL2 does not permit FLOAT readback
  // from it, unlike the desktop HDR checks' back_pixel helper.
  auto sample = [](int x, int y) {
    Target &back = textures[0];
    u8 rgba[4];
    glBindFramebuffer(GL_FRAMEBUFFER, back.framebuffer);
    glReadPixels(x * back.width / back.logical_width, y * back.height / back.logical_height,
                 1, 1, GL_RGBA, GL_UNSIGNED_BYTE, rgba);
    bind_target();
    return Pixel{rgba[0] / 255.f, rgba[1] / 255.f, rgba[2] / 255.f, rgba[3] / 255.f};
  };
  auto reference = draw(quads);
  Pixel left = sample(16, 32), right = sample(48, 32);
  assert(left.r == 1 && left.g == 0 && right.g == 1 && right.r == 0);
  // Streaming fallback, static quads, then a different fallback at the same
  // CPU address: neither buffer bindings nor a pointer's identity are content.
  assert(draw(reordered) == reference);
  renderer_present(128, 128);
  renderer_resume();
  assert(draw(quads) == reference);
  memcpy(reordered, quads, sizeof quads);
  std::swap(reordered[0], reordered[1]);
  assert(draw(reordered) == reference); // culling is disabled
  const unsigned short strip[] = {0, 1, 3, 2};
  draw(strip, 5, 2);
  assert(sample(16, 32).r == 1 && sample(48, 32).r == 0);
  assert(draw(quads) == reference);

  // The last representable uint16 index is valid in desktop GL. A full-range
  // static EBO must not wrap its final quad back onto the first one's indices.
#ifndef __EMSCRIPTEN__
  std::vector<Vertex> large(65536);
  std::copy(vertices, vertices + 4, large.end() - 4);
  std::vector<unsigned short> indices(QUAD_INDEX_COUNT);
  for (int i = 0; i < QUAD_INDEX_COUNT; i += 6) {
    unsigned short base = (unsigned short)(i / 6 * 4);
    unsigned short quad[] = {base, (unsigned short)(base + 1), (unsigned short)(base + 2),
                             (unsigned short)(base + 2), (unsigned short)(base + 3), base};
    std::copy(quad, quad + 6, indices.begin() + i);
  }
  w2c_host_clear(nullptr, 0xff000000);
  device_draw(textures[0], 4, large.data(), (u32)large.size(), indices.data(), QUAD_INDEX_COUNT / 3);
  assert(sample(16, 32).r == 1 && sample(48, 32).r == 0);
#endif

  // A companion can change the persistent sampler while desired device states
  // stay put. The next classic draw must restore those exact device settings.
  unsigned helper_states[32];
  memcpy(helper_states, stage_states[0], sizeof helper_states);
  helper_states[TSS_ADDRESSU] = 3;
  helper_states[TSS_MAGFILTER] = 1;
  w2c_host_texture_stage_state(nullptr, 0, TSS_ADDRESSU, 1);
  w2c_host_texture_stage_state(nullptr, 0, TSS_MAGFILTER, 2);
  draw(quads);
  apply_sampler(0, helper_states);
  assert(draw(quads) == reference);
  GLint wrap, filter;
  glGetSamplerParameteriv(samplers[0], GL_TEXTURE_WRAP_S, &wrap);
  glGetSamplerParameteriv(samplers[0], GL_TEXTURE_MAG_FILTER, &filter);
  assert(wrap == GL_REPEAT && filter == GL_LINEAR);

  // Change a texture-stage array and the factor, then return to the old state.
  w2c_host_texture_stage_state(nullptr, 0, TSS_COLORARG2, 3);
  for (u32 color : {0xffff0000u, 0xff0000ffu, 0xffff0000u}) {
    w2c_host_render_state(nullptr, RS_TEXTUREFACTOR, color);
    draw(quads);
    Pixel pixel = sample(48, 32);
    assert(pixel.r == (color == 0xffff0000u ? 1 : 0) && pixel.b == (color == 0xff0000ffu ? 1 : 0));
  }
  w2c_host_texture_stage_state(nullptr, 0, TSS_COLORARG2, 0);
  assert(draw(quads) == reference);
  assert(glGetError() == GL_NO_ERROR);
  puts("renderer: static quad indices, streaming fallback, helper sampler state and cached uniform transitions passed");
}


#ifndef __EMSCRIPTEN__
void check_ground_visibility() {
  // Bounds must include reflection-only reach, long segments and rings,
  // while sources wholly outside the view produce no fragments.
  GroundVisibility region;
  region.prepare(0, 0, 64, 64, 1, true);
  float p[4] = {200, 32, 5, 24}, d[4] = {1, 0, 0, 0}, c[4] = {}, r[4] = {0, 1, 180, 1}, shape[4] = {};
  auto bounds = [&] { return region.bounds(0, p, d, c, r, shape, true); };
  assert(bounds()[2] > 0); // reflection reach exceeds illumination radius
  r[2] = 5;
  assert(bounds()[2] == 0);
  d[3] = 400;
  assert(bounds()[2] > 0); // segment reaches the view though its center does not
  d[3] = 0; shape[3] = 200;
  assert(bounds()[2] > 0); // extended analytic beam support
  shape[3] = 0; c[3] = 180;
  assert(bounds()[2] > 0); // ring's near edge
  r[1] = 0;
  assert(bounds()[2] == 0); // no eligible response
  renderer_resize(128, 128);
  w2c_host_back_buffer(nullptr, 64, 64);
  w2c_host_set_render_target(nullptr, 0);
  assert(renderer_set_rtx(true));
  float lights[32 * RTX_LIGHT_FLOATS] = {};
  for (int i = 0; i < 32; ++i) {
    float *l = lights + i * RTX_LIGHT_FLOATS;
    l[0] = 32; l[1] = 4; l[2] = 100; l[3] = 24;
    l[4] = l[5] = l[6] = 1;
    l[13] = 1; l[14] = 100; l[15] = 2; l[16] = 1;
  }
  const float values[20] = {4, 1, 0, 0, 32, 24, 9.6f, 12,
                            .1f, .1f, 1 / 24.f, 1e20f, 1, 0, 1, 1e20f, 1, 0, 0, 0};
  auto begin = [&](int count, float camera_x, float shadows, bool bodies = true) {
    const float view[7] = {camera_x, 0, 0, 64, 64, 1, 1};
    const float grid[6] = {0, 0, bodies ? 1.f : 0.f, bodies ? 1.f : 0.f, 64, shadows};
    memcpy(memory + 4096, view, sizeof view);
    memcpy(memory + 8192, lights, sizeof lights);
    memcpy(memory + 16384, grid, sizeof grid);
    memcpy(memory + 16512, values, sizeof values);
    w2c_host_scene(nullptr, 4096, 8192, count);
    w2c_host_occlusion(nullptr, 16384, 16512, bodies ? 20 : 0);
    w2c_host_render_pass(nullptr, HOST_PASS_WORLD_BEGIN);
  };
  auto end = [] { w2c_host_render_pass(nullptr, HOST_PASS_WORLD_END); };
  auto mask = [](int index, float x, float y) {
    const GroundVisibility &v = ground_visibility;
    int group = index / 4;
    int px = group % 4 * v.width + (int)floorf((x - v.rect[0]) / GroundVisibility::texel);
    int py = group / 4 * v.height + (int)floorf((y - v.rect[1]) / GroundVisibility::texel);
    float rgba[4];
    glBindFramebuffer(GL_FRAMEBUFFER, beam_vis_framebuffer);
    glReadPixels(px, py, 1, 1, GL_RGBA, GL_FLOAT, rgba);
    bind_target();
    return rgba[index % 4];
  };
  // Reflection-only sources without beams get masks, including the last lane
  // of the last group. A body between the receiver and source darkens both.
  begin(32, 0, 1);
  assert(ground_visibility.count == 32 && !beam_lights);
  float blocked = mask(0, 31, 49);
  assert(blocked < .3f && fabsf(mask(31, 31, 49) - blocked) < 1e-3f);
  GLuint texture = beam_vis_texture;
  int width = beam_vis_width, height = beam_vis_height;
  end();
  // Visibility is scalar data: HDR color/gain changes never encode, clip or
  // rescale it. World sample positions also survive fractional/snapped pans.
  for (int i = 0; i < 32; ++i) {
    float *l = lights + i * RTX_LIGHT_FLOATS;
    l[4] = 64; l[5] = 8; l[6] = .25f; l[13] = 100;
  }
  for (float camera : {-.25f, 2.25f, -5.75f, 0.f}) {
    begin(32, camera, 1);
    assert(beam_vis_texture == texture && beam_vis_width == width && beam_vis_height == height);
    assert(fabsf(mask(31, 31, 49) - blocked) < 1e-3f);
    end();
  }
  begin(1, 0, 1);
  assert(mask(31, 31, 49) == 1); // unused groups must be cleared, not kept from the previous frame
  end();
  for (int state = 0; state < 3; ++state) {
    begin(state == 0 ? 0 : 1, 0, state == 1 ? 0 : 1, state != 2);
    assert(ground_visibility.count == 0 && ground_visibility.rect[2] == 0);
    end();
  }
  assert(!renderer_set_rtx(false));
  assert(!beam_vis_texture && !ground_visibility.count);
  assert(glGetError() == GL_NO_ERROR);
  puts("renderer: world-anchored scalar visibility, reflection-only sources, all 32 lanes and mask invalidation passed");
}
#endif

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
#if defined(RENDERER_BENCHMARK) && RENDERER_BENCHMARK == 0
  std::string baseline = fragment_source;
  for (const char *call : {"alphaCatmullRom(image, uv)", "alphaBilinear(image, uv)"}) {
    size_t at = baseline.find(call);
    assert(at != std::string::npos);
    baseline.replace(at, strlen(call), "texture(image, uv)");
  }
  fragment_source = baseline.c_str();
#endif
  renderer_init();
  renderer_resize(2048, 1536);
  w2c_host_back_buffer(nullptr, 1024, 768);
  assert(textures[0].width == 2048); // Correct on the very first draw, too.
  w2c_host_render_state(nullptr, RS_CULLMODE, 1);
  w2c_host_texture_stage_state(nullptr, 0, TSS_ALPHAOP, 3);
  stripes(98, 1024, 1);
  stripes(99, 1, 768);
  for (auto size : {std::pair{1024, 768}, {1280, 960}, {1600, 1200}, {2048, 1536},
                    {2300, 1540}, {2276, 1636}, {3840, 2160}, {1001, 777}, {400, 300}})
    check_fullscreen(size.first, size.second);
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

  // Grim's circles (host_circle) are round: a disc and a 2px band, covered within
  // three quarters of a logical pixel of their radii and clear beyond, where the
  // original's polygons cut up to 0.86 inside them.
  w2c_host_clear(nullptr, 0);
  w2c_host_render_state(nullptr, RS_ALPHABLENDENABLE, 1);
  w2c_host_render_state(nullptr, RS_SRCBLEND, 5);
  w2c_host_render_state(nullptr, RS_DESTBLEND, 6);
  const float circles[2][7] = {{300, 384, 0, 100, 0, 0, 0}, {700, 384, 100, 102, 0, 0, 1}};
  for (const float *shape : circles) {
    memcpy(memory, shape, sizeof circles[0]);
    w2c_host_circle(nullptr, 0, 0xffffffff);
  }
  pixels = renderer_capture(width, height);
  int partial = 0;
  for (const float *shape : circles)
    for (int y = 0; y < height; ++y)
      for (int x = 0; x < width; ++x) {
        // The pixel's center in the device's logical coordinates.
        float d = hypotf((x + .5f) / 2 - .5f - shape[0], (y + .5f) / 2 - .5f - shape[1]);
        if (d > shape[3] + 4)
          continue;
        u8 value = pixels[((size_t)y * width + x) * 4];
        if (d >= shape[3] + .75f || d <= shape[2] - .75f)
          assert(value == 0);
        else if (d <= shape[3] - .75f && d >= shape[2] + .75f)
          assert(value == 255);
        else
          partial += value > 0 && value < 255;
      }
  assert(partial > 1000); // Antialiased edges.
  w2c_host_render_state(nullptr, RS_ALPHABLENDENABLE, 0);

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

  // A copy kept on disk (host/watch_cache.inc): a target's pixels at the size
  // it is drawn, back into a target made like it, and refused by one of
  // another size.
  w2c_host_texture_create(nullptr, 11, 64, 32, 1);
  w2c_host_set_render_target(nullptr, 11);
  w2c_host_clear(nullptr, 0xff123456);
  rectangle(10, 10, 20.5f, 20, 0xffffffff);
  u32 size = w2c_host_texture_read(nullptr, 11, 4096, 0);
  assert(size == 128 * 64 * 4 && w2c_host_texture_read(nullptr, 11, 4096, size) == size);
  assert(!w2c_host_texture_write(nullptr, 12, 8, 4096, size));
  assert(w2c_host_texture_write(nullptr, 12, 11, 4096, size));
  assert(textures[12].width == 128 && textures[12].logical_width == 64);
  assert(w2c_host_texture_read(nullptr, 12, 4096 + size, size) == size);
  assert(!memcmp(memory + 4096, memory + 4096 + size, size));

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
  check_rtx();
#if !defined(RENDERER_BENCHMARK) || RENDERER_BENCHMARK != 0
  // A transparent blue texel must never turn the opaque red neighbor purple.
  w2c_host_texture_create(nullptr, 201, 2, 1, 0);
  const u8 edge_texels[] = {0, 0, 255, 255, 255, 0, 0, 0};
  memcpy(memory + 1024, edge_texels, sizeof edge_texels);
  w2c_host_texture_upload(nullptr, 201, 1024);
  w2c_host_set_texture(nullptr, 0, 201);
  w2c_host_set_texture(nullptr, 1, 0);
  w2c_host_texture_create(nullptr, 202, 16, 8, 3);
  w2c_host_set_render_target(nullptr, 202);
  w2c_host_render_state(nullptr, RS_ALPHABLENDENABLE, 0);
  w2c_host_render_state(nullptr, RS_ALPHATESTENABLE, 0);
  w2c_host_render_state(nullptr, RS_COLORWRITEENABLE, 15);
  w2c_host_texture_stage_state(nullptr, 0, TSS_COLOROP, 2);
  w2c_host_texture_stage_state(nullptr, 0, TSS_COLORARG1, 2);
  w2c_host_texture_stage_state(nullptr, 0, TSS_MINFILTER, 2);
  w2c_host_texture_stage_state(nullptr, 0, TSS_MAGFILTER, 2);
  w2c_host_texture_stage_state(nullptr, 0, TSS_ADDRESSU, 3);
  w2c_host_texture_stage_state(nullptr, 1, TSS_COLOROP, 1);
  for (int cubic : {0, 1}) {
    w2c_host_texture_stage_state(nullptr, 0, TSS_TERRAIN_ART, cubic);
    rectangle(0, 0, 16, 8, 0xffffffff);
    u8 edge[4];
    glReadPixels(15, 8, 1, 1, GL_RGBA, GL_UNSIGNED_BYTE, edge);
    assert(edge[0] == 255 && edge[1] == 0 && edge[2] == 0 && edge[3] == 255);
  }
  puts("renderer: associated bilinear and cubic reject transparent RGB contamination");
#endif
#ifndef RENDERER_BENCHMARK
  check_submission_reuse();
#ifndef __EMSCRIPTEN__
  check_ground_visibility();
#endif
#endif
#ifdef RENDERER_BENCHMARK
  benchmark(true);
  benchmark(false);
#endif
  SDL_GL_DestroyContext(context);
  SDL_DestroyWindow(window);
  SDL_Quit();
}
