// The browser build's renderer: WebGPU (renderer_webgpu.cpp) when the page got a
// device before the module started (shell.html), else WebGL2 (renderer.cpp). The
// choice holds for the session: a canvas keeps the first kind of context it gives.
#ifdef CLIENT_RENDERER_SELECT
#include "client.h"
#include <emscripten.h>

#define RENDERER_ENTRIES(X)                                                                                           \
  X(void, renderer_init, (), ())                                                                                      \
  X(Viewport, renderer_viewport, (int w, int h), (w, h))                                                              \
  X(void, renderer_resize, (int w, int h), (w, h))                                                                    \
  X(void, renderer_present, (int w, int h), (w, h))                                                                   \
  X(void, renderer_resume, (), ())                                                                                    \
  X(std::vector<unsigned char>, renderer_capture, (int &w, int &h), (w, h))                                           \
  X(bool, renderer_set_rtx, (bool enabled), (enabled))                                                                \
  X(void, renderer_set_headroom, (float headroom), (headroom))
#define HOST_ENTRIES(X)                                                                                               \
  X(frame_hold, (struct w2c_host * h, u32 op), (h, op))                                                               \
  X(texture_copy, (struct w2c_host * h, u32 d, u32 s), (h, d, s))                                                     \
  X(back_buffer, (struct w2c_host * h, u32 w, u32 hh), (h, w, hh))                                                    \
  X(texture_create, (struct w2c_host * h, u32 id, u32 w, u32 hh, u32 f), (h, id, w, hh, f))                           \
  X(texture_upload, (struct w2c_host * h, u32 id, u32 t), (h, id, t))                                                 \
  X(texture_release, (struct w2c_host * h, u32 id), (h, id))                                                          \
  X(render_state, (struct w2c_host * h, u32 s, u32 v), (h, s, v))                                                     \
  X(texture_stage_state, (struct w2c_host * h, u32 st, u32 s, u32 v), (h, st, s, v))                                  \
  X(set_texture, (struct w2c_host * h, u32 st, u32 id), (h, st, id))                                                  \
  X(set_render_target, (struct w2c_host * h, u32 id), (h, id))                                                        \
  X(clear, (struct w2c_host * h, u32 c), (h, c))                                                                      \
  X(draw, (struct w2c_host * h, u32 p, u32 v, u32 vc, u32 i, u32 pc), (h, p, v, vc, i, pc))                           \
  X(beam, (struct w2c_host * h, u32 c, f32 l, f32 s, u32 col), (h, c, l, s, col))                                     \
  X(render_pass, (struct w2c_host * h, u32 p), (h, p))                                                                \
  X(scene, (struct w2c_host * h, u32 c, u32 l, u32 n), (h, c, l, n))                                                  \
  X(occlusion, (struct w2c_host * h, u32 g, u32 v, u32 n), (h, g, v, n))                                              \
  X(bonus, (struct w2c_host * h, u32 e, f32 gx, f32 gy, f32 cx, f32 cy), (h, e, gx, gy, cx, cy))                      \
  X(ground, (struct w2c_host * h, u32 k, f32 s), (h, k, s))                                                           \
  X(smoke, (struct w2c_host * h, u32 c, u32 n), (h, c, n))                                                            \
  X(smoke_draw, (struct w2c_host * h, u32 v, u32 l, u32 nl, u32 s, u32 ns), (h, v, l, nl, s, ns))                     \
  X(gamma_ramp, (struct w2c_host * h, u32 r, u32 g, u32 b), (h, r, g, b))

#define DECLARE(type, name, params, args) type gl_##name params; type wgpu_##name params;
RENDERER_ENTRIES(DECLARE)
extern "C" {
#define DECLARE_HOST(name, params, args) void gl_w2c_host_##name params; void wgpu_w2c_host_##name params;
HOST_ENTRIES(DECLARE_HOST)
}

static bool webgpu() {
  static const bool chosen = EM_ASM_INT({ return Module.preinitializedWebGPUDevice ? 1 : 0; });
  return chosen;
}
bool renderer_uses_gl() { return !webgpu(); }

#define FORWARD(type, name, params, args)                                                                             \
  type name params { return webgpu() ? wgpu_##name args : gl_##name args; }
RENDERER_ENTRIES(FORWARD)
extern "C" {
#define FORWARD_HOST(name, params, args)                                                                              \
  void w2c_host_##name params { webgpu() ? wgpu_w2c_host_##name args : gl_w2c_host_##name args; }
HOST_ENTRIES(FORWARD_HOST)
}
#endif
