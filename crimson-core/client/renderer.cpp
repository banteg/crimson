// The Direct3D 8 subset the game module's device sends, on OpenGL 3.3 core
// (OpenGL ES 3.0 / WebGL2 in the browser). Render targets and the back buffer
// are framebuffer textures whose row 0 is the image's top row, as uploaded
// textures are; presenting flips the back buffer into the window. In RTX mode
// (game/rtx.cpp, native only) the world draws into a half-float target that a
// tonemap then puts on a half-float back buffer, so highlights can exceed white.
#include "../game/effect_vertices.h"
#include "client.h"
#include "client_shaders.h"
#include "device_states.h"
#include "ground_visibility.h"
#include "ice_surface.h"
#include <algorithm>
#include <chrono>
#include <deque>
#include <map>
#include <math.h>
#include <stdio.h>
#include <string.h>
#include <string>
#include <unordered_map>
#include <vector>
#ifdef __EMSCRIPTEN__
#include <GLES3/gl3.h>
#define SHADER_HEADER "#version 300 es\nprecision highp float;\nprecision highp int;\n"
#elif defined(__APPLE__)
#define GL_SILENCE_DEPRECATION
#include <OpenGL/gl3.h>
#define SHADER_HEADER "#version 330 core\n"
#else
#define GL_GLEXT_PROTOTYPES
#include <GL/gl.h>
#include <GL/glext.h>
#define SHADER_HEADER "#version 330 core\n"
#endif

// The browser build carries a WebGPU renderer too (renderer_webgpu.cpp) and picks
// one at startup (renderer_select.cpp): there these entry points are gl_*.
#ifdef CLIENT_RENDERER_SELECT
#define GL_ENTRY(name) gl_##name
#else
#define GL_ENTRY(name) name
bool renderer_uses_gl() { return true; }
#endif

// Each helper changes the same GL context. Keep the applied program and sampler
// state here, rather than inferring it from the host device's desired states.
namespace {
GLuint applied_program;
void use_program(GLuint id) {
  if (applied_program != id) {
    glUseProgram(id);
    applied_program = id;
  }
}
std::unordered_map<GLuint, std::unordered_map<std::string, GLint>> uniform_locations;
GLint uniform_location(GLuint id, const char *name) {
  auto &locations = uniform_locations[id];
  auto found = locations.find(name);
  if (found != locations.end())
    return found->second;
  GLint location = glGetUniformLocation(id, name);
  locations.emplace(name, location); // -1 (an inactive uniform) is cached too.
  return location;
}

// Compare the values sent to GL, including array contents, not their addresses.
// Unknown values always write, even when the desired value happens to be zero.
template <class T> struct AppliedValue {
  T value{};
  bool known = false;
  bool change(const T &next) {
    if (known && !memcmp(&value, &next, sizeof value))
      return false;
    memcpy(&value, &next, sizeof value);
    known = true;
    return true;
  }
};
struct ClassicUniforms {
  AppliedValue<float[2]> target_size;
  AppliedValue<GLint[STAGES]> has_texture, reconstruction, color_op, color_arg1, color_arg2;
  AppliedValue<GLint[STAGES]> alpha_op, alpha_arg1, alpha_arg2;
  AppliedValue<float[4]> factor, circle, circle_uv;
  AppliedValue<GLint> alpha_test, alpha_func, in_world, glint;
  AppliedValue<float> alpha_ref;
} classic_uniforms;
struct SamplerState {
  AppliedValue<GLint> wrap_s, wrap_t, mag, min;
} sampler_states[STAGES];
} // namespace

// The marked decal draws a bake queues for the terrain's companions (w2c_host_draw):
// drawn, or dropped with the companions of terrain `id`.
extern "C" {
void flush_ground_stamps();
void discard_ground_stamps(int id);
}

namespace {

// CRIMSON_PROFILE (client/main.cpp): each frame's passes, as the marks between
// them name them (gpu_mark), with the CPU time from one mark to the next and, on
// timed frames (gpu_every), the GPU time a timer query measures. A timed frame
// reads the earlier ones' queries, finished by then (a frame more than
// PROFILE_PENDING timed frames behind is waited on). Also the frame's draws by pass,
// texture and target (quads and the target pixels they cover), the scene's
// sizes the host imports send (profile_stat), and the targets the frame has.
// WebGL2 has no timer queries.
struct GpuTimer {
  const char *label;
  GLuint query;
  double cpu_at; // ms
};
#ifdef __EMSCRIPTEN__
const bool profiling = false;
#define GL_TIME_ELAPSED 0
#define glGetQueryObjectui64v(query, name, value)
#else
const bool profiling = getenv("CRIMSON_PROFILE");
#endif
// CRIMSON_PROFILE_GPU=<n>: the GPU's times on every n-th frame (8 by default; 0
// none, 1 all). On macOS ending or reading a timer query flushes the driver's
// command buffer, so a timed frame splits into one per pass: a GPU-bound frame
// then runs slower (about 4 ms late in a run) and waits in the pass after a
// costly one instead of at the swap. The frames in between run as they would.
const int gpu_every = !profiling ? 0 : getenv("CRIMSON_PROFILE_GPU") ? atoi(getenv("CRIMSON_PROFILE_GPU")) : 8;
bool gpu_timed; // this frame's passes are timed
constexpr size_t PROFILE_PENDING = 4;
struct PendingFrame {
  long long frame;
  std::vector<GpuTimer> timers;
};
std::vector<GpuTimer> gpu_frame;
std::deque<PendingFrame> gpu_pending;
std::vector<GLuint> gpu_queries;
long long profile_frames;
// The last frame's own record, and the GPU's records as they finish.
std::string profile_cpu;
bool profile_cpu_ready, profile_cpu_timed;
std::deque<std::pair<long long, std::string>> profile_gpu;
struct DrawCount {
  double quads = 0, pixels = 0;
};
std::map<std::string, DrawCount> draw_frame;
std::map<std::string, double> profile_scene;
void profile_stat(const char *key, double value) {
  if (profiling)
    profile_scene[key] += value;
}
double profile_now() {
  return std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now().time_since_epoch()).count();
}
void gpu_mark(const char *label) {
  if (!profiling || (!gpu_frame.empty() && !strcmp(gpu_frame.back().label, label)))
    return;
  GLuint query = 0;
  if (gpu_timed) {
    if (!gpu_frame.empty())
      glEndQuery(GL_TIME_ELAPSED);
    if (gpu_queries.empty()) {
      glGenQueries(1, &query);
    } else {
      query = gpu_queries.back();
      gpu_queries.pop_back();
    }
    glBeginQuery(GL_TIME_ELAPSED, query);
  }
  gpu_frame.push_back({label, query, profile_now()});
}
// Drawing off the back buffer outside the world's passes (terrain decal bakes,
// heat stamps, the kept frame) gets its own timer, so the `frame` timer keeps
// only the simulation's time; the label before it resumes after.
const char *gpu_resume_label;
void gpu_aside(const char *label) {
  if (!profiling || gpu_resume_label)
    return;
  gpu_resume_label = gpu_frame.empty() ? "frame" : gpu_frame.back().label;
  gpu_mark(label);
}
void gpu_resume() {
  if (!gpu_resume_label)
    return;
  gpu_mark(gpu_resume_label);
  gpu_resume_label = nullptr;
}
std::string json_string(const std::string &text) {
  std::string out = "\"";
  for (char c : text) {
    if (c == '"' || c == '\\')
      out += '\\';
    out += c;
  }
  return out + "\"";
}
// Labels in the order the frame first reached them, each with its summed time.
template <class Time> std::string pass_times(const std::vector<GpuTimer> &timers, Time time) {
  std::vector<std::pair<const char *, double>> totals;
  for (size_t i = 0; i < timers.size(); ++i) {
    auto it = std::find_if(totals.begin(), totals.end(), [&](const auto &p) { return !strcmp(p.first, timers[i].label); });
    (it == totals.end() ? totals.emplace_back(timers[i].label, 0.0) : *it).second += time(i);
  }
  std::string out;
  char entry[96];
  for (const auto &[label, ms] : totals) {
    snprintf(entry, sizeof entry, "%s\"%s\":%.3f", out.empty() ? "" : ",", label, ms);
    out += entry;
  }
  return "{" + out + "}";
}
struct Target {
  GLuint texture = 0, framebuffer = 0;
  // Texture storage and viewport pixels are independent of draw coordinates.
  int width = 0, height = 0, flags = 0;
  int logical_width = 0, logical_height = 0;
};
std::unordered_map<int, Target> textures; // id 0 is the back buffer
int current_target = 0;
int drawable_width = 0, drawable_height = 0;
unsigned render_states[256];
unsigned stage_states[STAGES][32];
int bound[STAGES];
GLuint program, present_program, vertex_array, vertex_buffer, index_buffer, quad_index_buffer, samplers[STAGES], gamma_texture;
// The lit creatures' quad centers (quad_centers), vertex attribute 3 while they draw.
GLuint center_buffer;
std::vector<float> centers;
// Bound to a stage with no texture: the shader never samples it, but a sampler
// needs a complete texture behind it.
GLuint blank_texture;
// The freeze ice's surface (HOST_PASS_ICE_*), on the creature program's thickness unit.
GLuint ice_texture;
GLint u_target_size, u_has_texture, u_color_op, u_color_arg1, u_color_arg2, u_alpha_op, u_alpha_arg1, u_alpha_arg2,
    u_factor, u_alpha_test, u_alpha_ref, u_alpha_func, u_reconstruction, u_circle, u_circle_uv, u_in_world, u_glint;
// RTX: the world's HDR target while the world draws (host_render_pass), and the
// tonemap that puts it on the back buffer toward the display's EDR headroom.
bool rtx, world;
Target hdr;
GLuint tonemap_program, beam_program, beam_array, beam_buffer;
GLuint effect_program;
GLint u_effect_target_size, u_effect_kind, u_effect_params, u_effect_in_world;
GLint u_tonemap_headroom, u_beam_target_size, u_beam_length, u_beam_step, u_beam_color, u_beam_in_world;
float edr_headroom = 1;

// The shaders WebGPU runs too (crimson-core/client/shaders, client/shaders.py).
const char *vertex_source = SHADER_HEADER SHADER_CLASSIC_VERT;
const char *fragment_source = SHADER_HEADER SHADER_CLASSIC_FRAG;
const char *present_vertex_source = SHADER_HEADER SHADER_PRESENT_VERT;
const char *present_fragment_source = SHADER_HEADER SHADER_PRESENT_FRAG;
// The Python port's RTX tonemap and analytic beam (src/crimson/render/rtx/shaders).
const char *tonemap_vertex_source = SHADER_HEADER SHADER_FULLSCREEN_VERT;
const char *tonemap_fragment_source = SHADER_HEADER RTX_SHADER_HDR_TONEMAP_FRAG;
const char *beam_vertex_source = SHADER_HEADER SHADER_BEAM_VERT;
const char *beam_fragment_source = SHADER_HEADER RTX_SHADER_BEAM_FRAG;
const char *lit_vertex_source = SHADER_HEADER SHADER_CREATURE_VERT;
const char *creature_lit_vertex_source = SHADER_HEADER SHADER_CREATURE_LIT_VERT;
const char *creature_fragment_source = SHADER_HEADER RTX_SHADER_CREATURE_FRAG;
const char *player_fragment_source = SHADER_HEADER RTX_SHADER_PLAYER_FRAG;
const char *bonus_fragment_source = SHADER_HEADER RTX_SHADER_BONUS_FRAG;
const char *ground_fragment_source = SHADER_HEADER SHADER_GROUND_LIT_FRAG;
const char *ground_beam_vis_source = SHADER_HEADER SHADER_GROUND_BEAM_VIS_FRAG;
const char *stamp_fragment_source = SHADER_HEADER RTX_SHADER_GROUND_STAMP_FRAG;
const char *smoke_rect_source = SHADER_HEADER SHADER_SMOKE_RECT_VERT;
const char *smoke_field_source = SHADER_HEADER SHADER_SMOKE_FIELD_VERT;
const char *smoke_solver_source = SHADER_HEADER RTX_SHADER_SMOKE_SOLVER_FRAG;
const char *smoke_splat_source = SHADER_HEADER RTX_SHADER_SMOKE_SPLAT_FRAG;
const char *smoke_impulse_source = SHADER_HEADER RTX_SHADER_SMOKE_IMPULSE_FRAG;
const char *smoke_fragment_source = SHADER_HEADER RTX_SHADER_SMOKE_FRAG;
const char *blit_fragment_source = SHADER_HEADER SHADER_BLIT_FRAG;
const char *heat_body_fragment_source = SHADER_HEADER RTX_SHADER_HEAT_BODY_FRAG;
const char *contact_glow_fragment_source = SHADER_HEADER RTX_SHADER_CONTACT_GLOW_FRAG;
const char *heat_stamp_fragment_source = SHADER_HEADER SHADER_HEAT_STAMP_FRAG;
const char *heat_trail_fragment_source = SHADER_HEADER SHADER_HEAT_TRAIL_LIT_FRAG;
const char *pressure_fragment_source = SHADER_HEADER SHADER_PRESSURE_LIT_FRAG;

// RTX lighting: the world's lights and camera (host_scene), the batch being drawn
// (HOST_PASS_CREATURES, _PLAYERS, MATERIAL_BONUS, or 0 for the device's own
// shading), and the creature, player and bonus programs, which light the
// device's vertices in the world. A bonus draw's own material (host_bonus): the
// shell or an emblem, its atlas's cell grid and the shell's center.
enum { MAX_LIGHTS = 32 };
int material;
float scene_camera[2];
GroundVisibility ground_visibility;
bool visibility_dirty = true;
float light_pos[MAX_LIGHTS * 4], light_rgb[MAX_LIGHTS * 4], light_dir[MAX_LIGHTS * 4], light_response[MAX_LIGHTS * 4];
int light_count;
// What the ground takes beyond them (host_scene): the run's clock, the terrain's
// size in world units, the beam sections' gains, and per light its direction
// with broad illumination, its reflection tail and its three beam sections.
float scene_seconds, ground_size[2], beam_gain[2];
float ground_dir[MAX_LIGHTS * 4], light_tail[MAX_LIGHTS], beam_shape[MAX_LIGHTS * 4];
bool beam_lights;
int bonus_emblem;
float bonus_grid[2], bonus_center[2];
struct LitProgram {
  GLuint id = 0;
  GLint target_size, camera, count, ambient, pos, rgb, dir, response, occlusion_grid, occlusion_cell, shadows;
  GLint pass, grid, shell_center, ice, ice_frozen;
};
// The creature body grid (host_occlusion): origin, columns (0 for none) and rows,
// cell size, the shadows setting, and its texels in an RGBA32F texture 256 wide.
enum { OCCLUSION_WIDTH = 256 };
float occlusion_grid[4], occlusion_cell = 64;
int dynamic_shadows;
// The grid rotates through three textures: an upload never waits for frames
// still reading the one before.
GLuint occlusion_textures[3], occlusion_texture;
int occlusion_texture_rows[3], occlusion_next;
std::vector<float> occlusion_texels;
LitProgram creature_lit, player_lit, bonus_lit;
// Monster Vision's heat (render/rtx/heat_vision.py): the bodies' program
// (HOST_PASS_HEAT), and the world-space trail buffer at half the terrain's
// resolution with the run's clock it last faded at (host_heat), its passes and
// the program that adds it to the ground (host_heat_trails).
const float HEAT_TRAIL_SCALE = 0.5f, HEAT_HALF_LIFE_S = 0.3f, HEAT_MAX_GAP_S = 1;
GLuint heat_body_program, heat_stamp_program, heat_trail_program;
// Ion arcs' contact glows on the ground (HOST_PASS_GLOW, render/rtx/contact_glow.py).
GLuint contact_glow_program;
Target heat_trail;
float heat_seconds = -1;
// The explosions' pressure fronts (host_pressure, render/rtx/shockwaves.py):
// screen center, radius and strength each, applied from the world's target into
// another before the tonemap reads it.
std::vector<float> pressure_fronts;
GLuint pressure_program;
Target pressured;
// The RTX ground (render/rtx/materials.py): companions of the terrain target,
// made from it as it stands on first use and dropped when it is cleared,
// replaced or released, or RTX ends. The substrate is the terrain and its decals
// without blood; coverage holds the ordered materials (blood, corpse, brass,
// ice); the float surface holds specularity, wetness, blood volume and height.
// Wetness is stored against an epoch, rebased as the clock runs on. Decal draws
// marked with a material (host_ground) reach them as they reach the terrain.
struct Ground {
  Target substrate, coverage, surface;
  float epoch = 0;
};
std::unordered_map<int, Ground> grounds;
int ground_kind = HOST_GROUND_END;
float ground_seconds;
GLuint ground_program, stamp_program, fill_program;
// World-space, color-independent source visibility: four source masks per
// RGBA group, four groups a row. Final shading never walks the body grid.
enum { BEAM_VISIBILITY_ROWS = MAX_LIGHTS / 16 };
GLuint ground_beam_vis_program, beam_vis_framebuffer, beam_vis_texture;
int beam_vis_width, beam_vis_height;
GLint u_stamp_target_size, u_stamp_kind, u_stamp_pass, u_stamp_wetness, u_fill_kind, u_fill_pass, u_fill_wetness;
// RTX fluid smoke (game/rtx_smoke.cpp, render/rtx/gpu_smoke.py): the field's
// RGBA16F targets (its state twice, divergence, pressure twice), the solver's
// settings and passes, and the display's composite at reduced resolution.
enum { SMOKE_TARGETS = 5, SMOKE_DISPLAY_MAX_AXIS = 640 };
Target smoke_targets[SMOKE_TARGETS], smoke_composite;
int smoke_current, smoke_iterations;
float smoke_resolution, smoke_world[2], smoke_dt, smoke_decay = 0.2f, smoke_fade = 1;
GLuint smoke_solver_program, smoke_splat_program, smoke_impulse_program, smoke_program, blit_program;
// Each uploaded artwork's texels in the module (it keeps them), for the creature
// thickness maps made on a creature atlas's first lit draw.
std::unordered_map<int, u32> texel_addresses;
std::unordered_map<int, GLuint> thickness_maps, heat_density_maps;

GLuint compile(GLenum kind, const char *source) {
  GLuint shader = glCreateShader(kind);
  glShaderSource(shader, 1, &source, nullptr);
  glCompileShader(shader);
  GLint ok;
  glGetShaderiv(shader, GL_COMPILE_STATUS, &ok);
  if (!ok) {
    char log[2048];
    glGetShaderInfoLog(shader, sizeof(log), nullptr, log);
    client_fatal(log);
  }
  return shader;
}
GLuint link(const char *vertex, const char *fragment) {
  GLuint p = glCreateProgram();
  glAttachShader(p, compile(GL_VERTEX_SHADER, vertex));
  glAttachShader(p, compile(GL_FRAGMENT_SHADER, fragment));
  glLinkProgram(p);
  GLint ok;
  glGetProgramiv(p, GL_LINK_STATUS, &ok);
  if (!ok)
    client_fatal("shader link failed");
  return p;
}

GLenum blend_factor(unsigned d3d) {
  switch (d3d) {
  case 1:
    return GL_ZERO;
  case 2:
    return GL_ONE;
  case 3:
    return GL_SRC_COLOR;
  case 4:
    return GL_ONE_MINUS_SRC_COLOR;
  case 5:
    return GL_SRC_ALPHA;
  case 6:
    return GL_ONE_MINUS_SRC_ALPHA;
  case 7:
    return GL_DST_ALPHA;
  case 8:
    return GL_ONE_MINUS_DST_ALPHA;
  case 9:
    return GL_DST_COLOR;
  case 10:
    return GL_ONE_MINUS_DST_COLOR;
  case 11:
    return GL_SRC_ALPHA_SATURATE;
  default:
    return GL_ONE;
  }
}
GLenum blend_equation(unsigned d3d) {
  switch (d3d) {
  case 2:
    return GL_FUNC_SUBTRACT;
  case 3:
    return GL_FUNC_REVERSE_SUBTRACT;
  case 4:
    return GL_MIN;
  case 5:
    return GL_MAX;
  default:
    return GL_FUNC_ADD;
  }
}
GLenum address(unsigned d3d) { return d3d == 2 ? GL_MIRRORED_REPEAT : d3d == 3 || d3d == 4 ? GL_CLAMP_TO_EDGE : GL_REPEAT; }

// The render states a draw writes its target with: blending and color writes.
void apply_output_state(const Target &t);

Target &target_or_back(int id) {
  auto it = textures.find(id);
  return it != textures.end() ? it->second : textures[0];
}

void allocate(Target &t) {
  glGenTextures(1, &t.texture);
  glBindTexture(GL_TEXTURE_2D, t.texture);
  if (t.flags & TARGET_FLOAT)
    glTexImage2D(GL_TEXTURE_2D, 0, GL_RGBA32F, t.width, t.height, 0, GL_RGBA, GL_FLOAT, nullptr);
  else if (t.flags & TARGET_HALF_FLOAT)
    glTexImage2D(GL_TEXTURE_2D, 0, GL_RGBA16F, t.width, t.height, 0, GL_RGBA, GL_HALF_FLOAT, nullptr);
  else
    glTexImage2D(GL_TEXTURE_2D, 0, GL_RGBA8, t.width, t.height, 0, GL_RGBA, GL_UNSIGNED_BYTE, nullptr);
  glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_LINEAR);
  glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_LINEAR);
  glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_S, GL_CLAMP_TO_EDGE);
  glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_T, GL_CLAMP_TO_EDGE);
  if (t.flags & 1) {
    glGenFramebuffers(1, &t.framebuffer);
    glBindFramebuffer(GL_FRAMEBUFFER, t.framebuffer);
    glFramebufferTexture2D(GL_FRAMEBUFFER, GL_COLOR_ATTACHMENT0, GL_TEXTURE_2D, t.texture, 0);
    if (glCheckFramebufferStatus(GL_FRAMEBUFFER) != GL_FRAMEBUFFER_COMPLETE)
      client_fatal("Could not allocate render target");
    // Direct3D's surfaces start black and opaque, whatever the last draw masked.
    glColorMask(GL_TRUE, GL_TRUE, GL_TRUE, GL_TRUE);
    glClearColor(0, 0, 0, 1);
    glClear(GL_COLOR_BUFFER_BIT);
  }
}

void release(Target &t) {
  if (t.framebuffer)
    glDeleteFramebuffers(1, &t.framebuffer);
  if (t.texture)
    glDeleteTextures(1, &t.texture);
  t = Target{};
}

// The RTX debug view the world shows (host_scene, game/rtx.cpp): 0 shaded, the
// ground's maps up to no-direct, then the smoke's. A map keeps only the ground's
// shade, or the smoke's, of the world: its other draws land in `discarded`.
enum { DEBUG_NO_DIRECT = 14, DEBUG_SMOKE = 15 };
int scene_debug;
bool smoke_drawing;
Target discarded;
bool debug_map() { return rtx && scene_debug && scene_debug != DEBUG_NO_DIRECT; }
bool world_kept() {
  return !debug_map() || (scene_debug >= DEBUG_SMOKE ? smoke_drawing : material == HOST_PASS_GROUND);
}

// Where a draw lands: while the RTX world draws, the back buffer's draws go to
// the HDR target.
Target &drawing_target(int id) {
  Target &t = target_or_back(id);
  return world && &t == &textures[0] ? world_kept() ? hdr : discarded : t;
}
// Whether a draw into `t` enters the world's linear light.
bool in_world(const Target &t) { return &t == &hdr || &t == &discarded; }

// Counts a draw for the timers: `what` it draws, its triangles as corner
// indices into x, y positions `stride` floats apart (the current target's
// logical units), `primitive` a device primitive (4 list, 5 strip, 6 fan).
void count_draw(const std::string &what, const float *positions, int stride, const unsigned short *indices,
                int primitive, int triangles) {
  if (!profiling || primitive < 4 || primitive > 6)
    return;
  Target &into = drawing_target(current_target);
  double scale = (double)into.width / std::max(1, into.logical_width), area = 0;
  for (int t = 0; t < triangles; ++t) {
    int k[3] = {primitive == 4 ? 3 * t : primitive == 5 ? t : 0, primitive == 4 ? 3 * t + 1 : t + 1,
                primitive == 4 ? 3 * t + 2 : t + 2};
    const float *a = positions + (indices ? indices[k[0]] : k[0]) * stride,
                *b = positions + (indices ? indices[k[1]] : k[1]) * stride,
                *c = positions + (indices ? indices[k[2]] : k[2]) * stride;
    area += fabs((b[0] - a[0]) * (c[1] - a[1]) - (c[0] - a[0]) * (b[1] - a[1])) * 0.5;
  }
  DrawCount &count = draw_frame[std::string(gpu_frame.empty() ? "frame" : gpu_frame.back().label) + ":" + what + ":" +
                                (current_target ? "t" + std::to_string(current_target) : world ? "world" : "back")];
  count.quads += triangles * 0.5;
  count.pixels += area * scale * scale;
}

void bind_target() {
  Target &t = drawing_target(current_target);
  glBindFramebuffer(GL_FRAMEBUFFER, t.framebuffer);
  glViewport(0, 0, t.width, t.height);
}

// Reallocate a target in place, keeping its image (scaled once if its size changed).
void reallocate(Target &t, int width, int height, int flags) {
  Target previous = t;
  t.texture = t.framebuffer = 0;
  t.width = width;
  t.height = height;
  t.flags = flags;
  allocate(t);
  glBindFramebuffer(GL_READ_FRAMEBUFFER, previous.framebuffer);
  glBindFramebuffer(GL_DRAW_FRAMEBUFFER, t.framebuffer);
  glBlitFramebuffer(0, 0, previous.width, previous.height, 0, 0, t.width, t.height, GL_COLOR_BUFFER_BIT,
                    previous.width == t.width && previous.height == t.height ? GL_NEAREST : GL_LINEAR);
  release(previous);
}

void apply_output_state(const Target &t) {
  if (render_states[RS_ALPHABLENDENABLE]) {
    glEnable(GL_BLEND);
    glBlendFunc(blend_factor(render_states[RS_SRCBLEND]), blend_factor(render_states[RS_DESTBLEND]));
    glBlendEquation(blend_equation(render_states[RS_BLENDOP]));
  } else {
    glDisable(GL_BLEND);
  }
  unsigned mask = render_states[RS_COLORWRITEENABLE];
  // An X8R8G8B8 surface keeps its alpha at one.
  glColorMask(mask & 1, mask & 2, mask & 4, (mask & 8) && !(t.flags & 2));
}

void apply_sampler(int stage, const unsigned *states) {
  SamplerState &s = sampler_states[stage];
  GLint wrap_s = address(states[TSS_ADDRESSU]), wrap_t = address(states[TSS_ADDRESSV]);
  GLint mag = states[TSS_MAGFILTER] >= 2 ? GL_LINEAR : GL_NEAREST;
  GLint min = states[TSS_MINFILTER] >= 2 ? GL_LINEAR : GL_NEAREST;
  if (s.wrap_s.change(wrap_s)) glSamplerParameteri(samplers[stage], GL_TEXTURE_WRAP_S, wrap_s);
  if (s.wrap_t.change(wrap_t)) glSamplerParameteri(samplers[stage], GL_TEXTURE_WRAP_T, wrap_t);
  if (s.mag.change(mag)) glSamplerParameteri(samplers[stage], GL_TEXTURE_MAG_FILTER, mag);
  if (s.min.change(min)) glSamplerParameteri(samplers[stage], GL_TEXTURE_MIN_FILTER, min);
}

void create_lit(LitProgram &p, const char *vertex, const char *fragment) {
  p.id = link(vertex, fragment);
  use_program(p.id);
  glUniform1i(uniform_location(p.id, "texture0"), 0);
  glUniform1i(uniform_location(p.id, "u_thickness"), 1);
  glUniform1i(uniform_location(p.id, "u_occlusion_tex"), 2);
  glUniform4f(uniform_location(p.id, "colDiffuse"), 1, 1, 1, 1);
  p.target_size = uniform_location(p.id, "target_size");
  p.camera = uniform_location(p.id, "camera");
  p.count = uniform_location(p.id, "u_count");
  p.ambient = uniform_location(p.id, "u_ambient");
  p.pos = uniform_location(p.id, "u_pos");
  p.rgb = uniform_location(p.id, "u_rgb");
  p.dir = uniform_location(p.id, "u_dir");
  p.response = uniform_location(p.id, "u_response");
  p.occlusion_grid = uniform_location(p.id, "u_occlusion_grid");
  p.occlusion_cell = uniform_location(p.id, "u_occlusion_cell_size");
  p.shadows = uniform_location(p.id, "u_dynamic_shadows");
  p.pass = uniform_location(p.id, "u_pass");
  p.grid = uniform_location(p.id, "u_grid");
  p.shell_center = uniform_location(p.id, "u_shell_center");
  p.ice = uniform_location(p.id, "u_ice");
  p.ice_frozen = uniform_location(p.id, "u_ice_frozen");
}

// A creature atlas's transmission part sizes or Monster Vision silhouette
// density, made once on first use (creature_translucency.py).
GLuint shape_map(int id, bool heat = false) {
  auto &maps = heat ? heat_density_maps : thickness_maps;
  auto made = maps.find(id);
  if (made != maps.end())
    return made->second;
  auto t = textures.find(id);
  auto texels = texel_addresses.find(id);
  if ((!light_count && !heat) || t == textures.end() || texels == texel_addresses.end())
    return blank_texture;
  int width = t->second.logical_width, height = t->second.logical_height;
  const auto *pixels = client_memory() + texels->second;
  std::vector<unsigned char> sizes =
      heat ? renderer_heat_density(pixels, width, height) : renderer_thickness(pixels, width, height);
  GLuint texture;
  glGenTextures(1, &texture);
  glBindTexture(GL_TEXTURE_2D, texture);
  glPixelStorei(GL_UNPACK_ALIGNMENT, 1);
  glTexImage2D(GL_TEXTURE_2D, 0, GL_R8, width, height, 0, GL_RED, GL_UNSIGNED_BYTE, sizes.data());
  glPixelStorei(GL_UNPACK_ALIGNMENT, 4);
  glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_LINEAR);
  glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_LINEAR);
  glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_S, GL_CLAMP_TO_EDGE);
  glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_T, GL_CLAMP_TO_EDGE);
  return maps[id] = texture;
}

// The device's vertices and indices as host_draw sends them.
// A primitive's indices: Direct3D counts primitives, GL indices.
int index_count(u32 primitive, u32 primitive_count) {
  return primitive == 4 ? primitive_count * 3 : primitive == 5 || primitive == 6 ? primitive_count + 2
         : primitive == 2 ? primitive_count * 2 : primitive == 3 ? primitive_count + 1 : primitive_count;
}
// Grim's shared quad indices cover the full uint16 vertex range. Arbitrary
// indexed triangles, strips and fans still use the streaming index buffer.
constexpr int QUAD_INDEX_COUNT = (65536 / 4) * 6;
bool canonical_quad_indices(u32 primitive, const unsigned short *indices, int count) {
  if (primitive != 4 || !indices || count <= 0 || count > QUAD_INDEX_COUNT || count % 6)
    return false;
  for (int i = 0; i < count; i += 6) {
    int base = i / 6 * 4;
    if (indices[i] != base || indices[i + 1] != base + 1 || indices[i + 2] != base + 2 ||
        indices[i + 3] != base + 2 || indices[i + 4] != base + 3 || indices[i + 5] != base)
      return false;
  }
  return true;
}
void submit_geometry(u32 primitive, const void *vertices, u32 vertex_count, const unsigned short *indices,
                     u32 primitive_count) {
  static const GLenum modes[] = {GL_POINTS, GL_POINTS, GL_LINES, GL_LINE_STRIP, GL_TRIANGLES, GL_TRIANGLE_STRIP, GL_TRIANGLE_FAN};
  GLenum mode = primitive < 7 ? modes[primitive] : GL_TRIANGLES;
  glBindVertexArray(vertex_array);
  glBindBuffer(GL_ARRAY_BUFFER, vertex_buffer);
  glBufferData(GL_ARRAY_BUFFER, (GLsizeiptr)vertex_count * 28, vertices, GL_STREAM_DRAW);
  int count = index_count(primitive, primitive_count);
  if (indices) {
    bool quads = canonical_quad_indices(primitive, indices, count);
    glBindBuffer(GL_ELEMENT_ARRAY_BUFFER, quads ? quad_index_buffer : index_buffer);
    if (!quads)
      glBufferData(GL_ELEMENT_ARRAY_BUFFER, (GLsizeiptr)count * 2, indices, GL_STREAM_DRAW);
    glDrawElements(mode, count, GL_UNSIGNED_SHORT, nullptr);
  } else {
    glDrawArrays(mode, 0, count);
  }
}
void submit_geometry(u32 primitive, u32 vertices, u32 vertex_count, u32 indices, u32 primitive_count) {
  submit_geometry(primitive, client_memory() + vertices, vertex_count,
                  indices ? (const unsigned short *)(client_memory() + indices) : nullptr, primitive_count);
}

// A creature batch drawn again as heat (heat_body.frag): the atlas and its
// smooth silhouette density, blended as the device's states say.
bool heat_draw(Target &t, u32 primitive, u32 vertices, u32 vertex_count, u32 indices, u32 primitive_count) {
  use_program(heat_body_program);
  glUniform2f(uniform_location(heat_body_program, "target_size"), (float)t.logical_width, (float)t.logical_height);
  glUniform2f(uniform_location(heat_body_program, "camera"), scene_camera[0], scene_camera[1]);
  auto it = textures.find(bound[0]);
  bool present = bound[0] && it != textures.end() && it->second.texture;
  glActiveTexture(GL_TEXTURE0);
  glBindTexture(GL_TEXTURE_2D, present ? it->second.texture : blank_texture);
  glBindSampler(0, 0);
  glActiveTexture(GL_TEXTURE1);
  glBindTexture(GL_TEXTURE_2D, present ? shape_map(bound[0], true) : blank_texture);
  glBindSampler(1, 0);
  glActiveTexture(GL_TEXTURE0);
  apply_output_state(t);
  glDisable(GL_CULL_FACE);
  submit_geometry(primitive, vertices, vertex_count, indices, primitive_count);
  return true;
}

// Ion arcs' contact glows (contact_glow.frag): discs over the quads' UVs in
// their vertex colors, blended as the device's states say.
bool glow_draw(Target &t, u32 primitive, u32 vertices, u32 vertex_count, u32 indices, u32 primitive_count) {
  use_program(contact_glow_program);
  glUniform2f(uniform_location(contact_glow_program, "target_size"), (float)t.logical_width, (float)t.logical_height);
  glUniform2f(uniform_location(contact_glow_program, "camera"), scene_camera[0], scene_camera[1]);
  apply_output_state(t);
  glDisable(GL_CULL_FACE);
  submit_geometry(primitive, vertices, vertex_count, indices, primitive_count);
  return true;
}

// A draw in an RTX creature, player or bonus batch, lit as the Python port
// lights them: creatures (their ambient fill is 0.6) and bonuses always, players
// only under lights.
bool lit_draw(u32 primitive, u32 vertices, u32 vertex_count, u32 indices, u32 primitive_count) {
  if (!rtx || !world || !material || material == HOST_PASS_GLINT || material == HOST_PASS_GROUND || (material == HOST_PASS_PLAYERS && !light_count))
    return false;
  Target &t = drawing_target(current_target);
  if (material == HOST_PASS_HEAT)
    return heat_draw(t, primitive, vertices, vertex_count, indices, primitive_count);
  if (material == HOST_PASS_GLOW)
    return glow_draw(t, primitive, vertices, vertex_count, indices, primitive_count);
  LitProgram &p = material == HOST_PASS_PLAYERS ? player_lit
                  : material == MATERIAL_BONUS  ? bonus_lit
                                                : creature_lit;
  use_program(p.id);
  glUniform1i(p.pass, bonus_emblem);
  int ice = material == HOST_PASS_ICE_CUBES || material == HOST_PASS_ICE_FROZEN ? 4 : material == HOST_PASS_ICE_SHARDS ? 8 : 0;
  glUniform1i(p.ice, ice);
  glUniform1i(p.ice_frozen, material == HOST_PASS_ICE_FROZEN);
  glUniform2fv(p.grid, 1, bonus_grid);
  glUniform2fv(p.shell_center, 1, bonus_center);
  glUniform2f(p.target_size, (float)t.logical_width, (float)t.logical_height);
  glUniform2f(p.camera, scene_camera[0], scene_camera[1]);
  glUniform1i(p.count, light_count);
  glUniform1f(p.ambient, 0.6f);
  glUniform4fv(p.occlusion_grid, 1, occlusion_grid);
  glUniform1f(p.occlusion_cell, occlusion_cell);
  glUniform1i(p.shadows, dynamic_shadows);
  if (light_count) {
    glUniform4fv(p.pos, light_count, light_pos);
    glUniform4fv(p.rgb, light_count, light_rgb);
    glUniform4fv(p.dir, light_count, light_dir);
    glUniform4fv(p.response, light_count, light_response);
  }
  auto it = textures.find(bound[0]);
  bool present = bound[0] && it != textures.end() && it->second.texture;
  glActiveTexture(GL_TEXTURE0);
  glBindTexture(GL_TEXTURE_2D, present ? it->second.texture : blank_texture);
  glBindSampler(0, samplers[0]);
  apply_sampler(0, stage_states[0]);
  glActiveTexture(GL_TEXTURE1);
  glBindTexture(GL_TEXTURE_2D, ice                                         ? ice_texture
                               : material == HOST_PASS_CREATURES && present ? shape_map(bound[0])
                                                                            : blank_texture);
  glBindSampler(1, 0);
  glActiveTexture(GL_TEXTURE2);
  glBindTexture(GL_TEXTURE_2D, occlusion_grid[2] ? occlusion_texture : blank_texture);
  glBindSampler(2, 0);
  glActiveTexture(GL_TEXTURE0);
  apply_output_state(t);
  glDisable(GL_CULL_FACE);
  bool creatures = &p == &creature_lit;
  if (creatures) {
    centers.resize((size_t)vertex_count * 2);
    quad_centers((const float *)(client_memory() + vertices), vertex_count, centers.data());
    glBindVertexArray(vertex_array);
    glBindBuffer(GL_ARRAY_BUFFER, center_buffer);
    glBufferData(GL_ARRAY_BUFFER, (GLsizeiptr)(centers.size() * sizeof(float)), centers.data(), GL_STREAM_DRAW);
    glEnableVertexAttribArray(3);
  }
  submit_geometry(primitive, vertices, vertex_count, indices, primitive_count);
  if (creatures)
    glDisableVertexAttribArray(3);
  return true;
}

// A ground pass over a whole companion: the stamp shader's `kind` and `pass`
// over `source`, into the bound framebuffer.
void ground_fill(GLuint source, int kind, int pass, float wetness) {
  use_program(fill_program);
  glUniform1i(u_fill_kind, kind);
  glUniform1i(u_fill_pass, pass);
  glUniform1f(u_fill_wetness, wetness);
  glActiveTexture(GL_TEXTURE0);
  glBindTexture(GL_TEXTURE_2D, source);
  glBindSampler(0, 0);
  glDisable(GL_CULL_FACE);
  glBindVertexArray(vertex_array);
  glDrawArrays(GL_TRIANGLE_STRIP, 0, 4);
}

void bind_framebuffer(const Target &t) {
  glBindFramebuffer(GL_FRAMEBUFFER, t.framebuffer);
  glViewport(0, 0, t.width, t.height);
}

void drop_ground(int id) {
  discard_ground_stamps(id);
  auto it = grounds.find(id);
  if (it == grounds.end())
    return;
  release(it->second.substrate);
  release(it->second.coverage);
  release(it->second.surface);
  grounds.erase(it);
}

// The companions of the terrain target `id`, made from it as it stands: the
// substrate a copy, no materials, and the surface's terrain pass (kind 0).
Ground &ground_of(int id) {
  auto made = grounds.find(id);
  if (made != grounds.end())
    return made->second;
  Target &albedo = textures[id];
  Ground &g = grounds[id];
  for (Target *t : {&g.substrate, &g.coverage, &g.surface}) {
    t->width = albedo.width, t->height = albedo.height;
    t->logical_width = albedo.logical_width, t->logical_height = albedo.logical_height;
    t->flags = t == &g.substrate ? albedo.flags : TARGET_RENDER | (t == &g.surface ? TARGET_FLOAT : 0);
    allocate(*t);
  }
  glBindFramebuffer(GL_READ_FRAMEBUFFER, albedo.framebuffer);
  glBindFramebuffer(GL_DRAW_FRAMEBUFFER, g.substrate.framebuffer);
  glBlitFramebuffer(0, 0, albedo.width, albedo.height, 0, 0, albedo.width, albedo.height, GL_COLOR_BUFFER_BIT,
                    GL_NEAREST);
  glColorMask(GL_TRUE, GL_TRUE, GL_TRUE, GL_TRUE);
  bind_framebuffer(g.coverage);
  glClearColor(0, 0, 0, 0);
  glClear(GL_COLOR_BUFFER_BIT);
  bind_framebuffer(g.surface);
  glClearColor(10 / 255.0f, 0, 0, 115 / 255.0f);
  glClear(GL_COLOR_BUFFER_BIT);
  glDisable(GL_BLEND);
  ground_fill(g.substrate.texture, 0, 0, 0);
  bind_target();
  return g;
}

// Wetness against a later epoch: its channel scaled by exp((old - new) / 45).
void rebase_wetness(Ground &g, float epoch) {
  bind_framebuffer(g.surface);
  glEnable(GL_BLEND);
  glBlendEquation(GL_FUNC_ADD);
  glBlendFunc(GL_ZERO, GL_SRC_COLOR);
  glColorMask(GL_FALSE, GL_TRUE, GL_FALSE, GL_FALSE);
  ground_fill(blank_texture, 0, 3, expf((g.epoch - epoch) / 45));
  g.epoch = epoch;
}

// A rect of a smoke target through one of the solver's programs, its uniforms set.
void smoke_rect(GLuint p, const float *rect) {
  glUniform4fv(uniform_location(p, "rect"), 1, rect);
  glUniform2f(uniform_location(p, "u_resolution"), smoke_resolution, smoke_resolution);
  glUniform2fv(uniform_location(p, "u_world_size"), 1, smoke_world);
  glDisable(GL_CULL_FACE);
  glBindVertexArray(vertex_array);
  glDrawArrays(GL_TRIANGLE_STRIP, 0, 4);
}

// A whole-field solver pass (GpuSmokeSimulation._pass): `mode` from `source`,
// with `aux` (pressure or divergence), into `destination`.
void smoke_pass(int destination, int source, int mode, int aux = -1) {
  bind_framebuffer(smoke_targets[destination]);
  glDisable(GL_BLEND);
  glColorMask(GL_TRUE, GL_TRUE, GL_TRUE, GL_TRUE);
  GLuint p = smoke_solver_program;
  use_program(p);
  glUniform1i(uniform_location(p, "texture0"), 0);
  glUniform1i(uniform_location(p, "u_aux"), 1);
  glUniform1i(uniform_location(p, "u_mode"), mode);
  glUniform1f(uniform_location(p, "u_dt"), smoke_dt);
  glUniform1f(uniform_location(p, "u_decay"), smoke_decay);
  glUniform1f(uniform_location(p, "u_fade"), smoke_fade);
  glActiveTexture(GL_TEXTURE1);
  glBindTexture(GL_TEXTURE_2D, aux >= 0 ? smoke_targets[aux].texture : blank_texture);
  glBindSampler(1, 0);
  glActiveTexture(GL_TEXTURE0);
  glBindTexture(GL_TEXTURE_2D, smoke_targets[source].texture);
  glBindSampler(0, 0);
  const float whole[4] = {0, 0, 1, 1};
  smoke_rect(p, whole);
}

void clear_smoke_target(int index) {
  bind_framebuffer(smoke_targets[index]);
  glColorMask(GL_TRUE, GL_TRUE, GL_TRUE, GL_TRUE);
  glClearColor(0, 0, 0, 0);
  glClear(GL_COLOR_BUFFER_BIT);
}

// Splats and impulses add into the state: its alpha is signed velocity, so ONE/ONE.
void smoke_add(GLuint p, const float *rect) {
  bind_framebuffer(smoke_targets[smoke_current]);
  glColorMask(GL_TRUE, GL_TRUE, GL_TRUE, GL_TRUE);
  glEnable(GL_BLEND);
  glBlendEquation(GL_FUNC_ADD);
  glBlendFunc(GL_ONE, GL_ONE);
  smoke_rect(p, rect);
}

// Device vertices the host makes (x, y, z, rhw, D3DCOLOR, u, v), as a triangle list.
struct HostVertex {
  float x, y, z, rhw;
  u32 color;
  float u, v;
};
void submit_vertices(const std::vector<HostVertex> &vertices) {
  glBindVertexArray(vertex_array);
  glBindBuffer(GL_ARRAY_BUFFER, vertex_buffer);
  glBufferData(GL_ARRAY_BUFFER, (GLsizeiptr)(vertices.size() * sizeof(HostVertex)), vertices.data(), GL_STREAM_DRAW);
  glDrawArrays(GL_TRIANGLES, 0, (GLsizei)vertices.size());
}

// Prepare the color-independent masks before opening the HDR world pass. A
// late scene/occlusion import can also rebuild them before the next ground draw.
void prepare_ground_visibility(int view_width, int view_height) {
  visibility_dirty = false;
  ground_visibility.prepare(scene_camera[0], scene_camera[1], (float)view_width, (float)view_height,
                            light_count, dynamic_shadows && occlusion_grid[2] > 0 &&
                            ground_size[0] > 0 && ground_size[1] > 0);
  const GroundVisibility &v = ground_visibility;
  profile_stat("ground_visibility_sources", v.count);
  profile_stat("ground_visibility_groups", (v.count + 3) / 4);
  if (!v.count)
    return;
  gpu_aside("ground-vis");
  if (!beam_vis_framebuffer || v.width != beam_vis_width || v.height != beam_vis_height) {
    if (!beam_vis_framebuffer) {
      glGenFramebuffers(1, &beam_vis_framebuffer);
      glGenTextures(1, &beam_vis_texture);
    }
    glBindTexture(GL_TEXTURE_2D, beam_vis_texture);
    glTexImage2D(GL_TEXTURE_2D, 0, GL_RGBA16F, 4 * v.width, BEAM_VISIBILITY_ROWS * v.height,
                 0, GL_RGBA, GL_HALF_FLOAT, nullptr);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_LINEAR);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_LINEAR);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_S, GL_CLAMP_TO_EDGE);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_T, GL_CLAMP_TO_EDGE);
    glBindFramebuffer(GL_FRAMEBUFFER, beam_vis_framebuffer);
    glFramebufferTexture2D(GL_FRAMEBUFFER, GL_COLOR_ATTACHMENT0, GL_TEXTURE_2D, beam_vis_texture, 0);
    beam_vis_width = v.width;
    beam_vis_height = v.height;
  }
  glBindFramebuffer(GL_FRAMEBUFFER, beam_vis_framebuffer);
  glDisable(GL_BLEND);
  glDisable(GL_CULL_FACE);
  glColorMask(GL_TRUE, GL_TRUE, GL_TRUE, GL_TRUE);
  glViewport(0, 0, 4 * v.width, BEAM_VISIBILITY_ROWS * v.height);
  glDisable(GL_SCISSOR_TEST);
  glClearColor(1, 1, 1, 1);
  glClear(GL_COLOR_BUFFER_BIT);
  GLuint p = ground_beam_vis_program;
  use_program(p);
  auto at = [p](const char *name) { return uniform_location(p, name); };
  glUniform4fv(at("u_visibility_world"), 1, v.rect);
  glUniform2fv(at("u_ground_size"), 1, ground_size);
  glUniform1i(at("u_spec_light_count"), light_count);
  glUniform1i(at("u_has_beam_lights"), beam_lights);
  glUniform4fv(at("u_spec_pos"), light_count, light_pos);
  glUniform4fv(at("u_spec_color"), light_count, light_rgb);
  glUniform4fv(at("u_spec_dir"), light_count, ground_dir);
  glUniform4fv(at("u_spec_response"), light_count, light_response);
  glUniform4fv(at("u_beam_shape"), light_count, beam_shape);
  glUniform4fv(at("u_occlusion_grid"), 1, occlusion_grid);
  glUniform1f(at("u_occlusion_cell_size"), occlusion_cell);
  glUniform1i(at("u_occlusion_tex"), 0);
  glActiveTexture(GL_TEXTURE0);
  glBindTexture(GL_TEXTURE_2D, occlusion_texture);
  glBindSampler(0, 0);
  glBindVertexArray(vertex_array);
  glEnable(GL_SCISSOR_TEST);
  for (int group = 0; group * 4 < v.count; ++group) {
    auto bounds = v.bounds(group, light_pos, ground_dir, light_rgb, light_response, beam_shape, beam_lights);
    if (!bounds[2] || !bounds[3]) continue;
    glScissor(group % 4 * v.width + bounds[0], group / 4 * v.height + bounds[1], bounds[2], bounds[3]);
    glViewport(group % 4 * v.width, group / 4 * v.height, v.width, v.height);
    glUniform1f(at("u_visibility_group"), (float)group);
    glDrawArrays(GL_TRIANGLE_STRIP, 0, 4);
  }
  glDisable(GL_SCISSOR_TEST);
  bind_target();
  gpu_resume();
}

// Full-resolution material shading samples one coarse RGBA group per four
// lights. No body-grid texture or shadow walk is bound to this program.
bool ground_draw(u32 primitive, u32 vertices, u32 vertex_count, u32 indices, u32 primitive_count) {
  flush_ground_stamps();
  auto it = textures.find(bound[0]);
  if (!bound[0] || it == textures.end() || !it->second.framebuffer)
    return false;
  Ground &g = ground_of(bound[0]);
  Target &t = drawing_target(current_target);
  if (visibility_dirty)
    prepare_ground_visibility(t.logical_width, t.logical_height);
  gpu_mark("ground-shade");
  GLuint p = ground_program;
  use_program(p);
  auto at = [p](const char *name) { return uniform_location(p, name); };
  glUniform2f(at("target_size"), (float)t.logical_width, (float)t.logical_height);
  glUniform2f(at("camera"), scene_camera[0], scene_camera[1]);
  glUniform2fv(at("u_ground_size"), 1, ground_size);
  glUniform1f(at("u_time_s"), scene_seconds - g.epoch);
  glUniform1i(at("u_debug"), scene_debug < DEBUG_SMOKE ? scene_debug : 0);
  glUniform1i(at("u_debug_display"), 1);
  glUniform1i(at("u_spec_light_count"), light_count);
  glUniform1i(at("u_has_beam_lights"), beam_lights);
  glUniform2fv(at("u_beam_gain"), 1, beam_gain);
  glUniform4fv(at("u_visibility_world"), 1, ground_visibility.rect);
  glUniform2f(at("u_visibility_size"), (float)std::max(1, beam_vis_width), (float)std::max(1, beam_vis_height));
  if (light_count) {
    glUniform4fv(at("u_spec_pos"), light_count, light_pos);
    glUniform4fv(at("u_spec_color"), light_count, light_rgb);
    glUniform4fv(at("u_spec_dir"), light_count, ground_dir);
    glUniform4fv(at("u_spec_response"), light_count, light_response);
    glUniform4fv(at("u_spec_tail"), (light_count + 3) / 4, light_tail);
    glUniform4fv(at("u_beam_shape"), light_count, beam_shape);
  }
  const GLuint inputs[] = {g.substrate.texture, g.surface.texture, g.coverage.texture,
                           ground_visibility.count ? beam_vis_texture : blank_texture};
  const char *names[] = {"u_substrate_tex", "u_surface_tex", "u_material_tex", "u_visibility_tex"};
  for (int i = 0; i < 4; ++i) {
    glUniform1i(at(names[i]), i);
    glActiveTexture(GL_TEXTURE0 + i);
    glBindTexture(GL_TEXTURE_2D, inputs[i]);
    glBindSampler(i, 0);
  }
  glActiveTexture(GL_TEXTURE0);
  apply_output_state(t);
  glDisable(GL_BLEND);
  glDisable(GL_CULL_FACE);
  submit_geometry(primitive, vertices, vertex_count, indices, primitive_count);
  return true;
}

} // namespace

void GL_ENTRY(renderer_init)() {
  applied_program = 0;
  uniform_locations.clear();
  classic_uniforms = {};
  for (SamplerState &s : sampler_states)
    s = {};
  program = link(vertex_source, fragment_source);
  present_program = link(present_vertex_source, present_fragment_source);
  u_target_size = uniform_location(program, "target_size");
  u_has_texture = uniform_location(program, "has_texture");
  u_reconstruction = uniform_location(program, "reconstruction");
  u_color_op = uniform_location(program, "color_op");
  u_color_arg1 = uniform_location(program, "color_arg1");
  u_color_arg2 = uniform_location(program, "color_arg2");
  u_alpha_op = uniform_location(program, "alpha_op");
  u_alpha_arg1 = uniform_location(program, "alpha_arg1");
  u_alpha_arg2 = uniform_location(program, "alpha_arg2");
  u_factor = uniform_location(program, "factor");
  u_alpha_test = uniform_location(program, "alpha_test");
  u_alpha_ref = uniform_location(program, "alpha_ref");
  u_alpha_func = uniform_location(program, "alpha_func");
  u_circle = uniform_location(program, "circle");
  u_circle_uv = uniform_location(program, "circle_uv");
  u_in_world = uniform_location(program, "in_world");
  u_glint = uniform_location(program, "glint");
  use_program(program);
  glUniform1i(uniform_location(program, "texture0"), 0);
  glUniform1i(uniform_location(program, "texture1"), 1);
  use_program(present_program);
  glUniform1i(uniform_location(present_program, "back_buffer"), 0);
  glUniform1i(uniform_location(present_program, "gamma"), 1);

  glGenVertexArrays(1, &vertex_array);
  glBindVertexArray(vertex_array);
  glGenBuffers(1, &vertex_buffer);
  glGenBuffers(1, &index_buffer);
  glGenBuffers(1, &quad_index_buffer);
  std::vector<unsigned short> quad_indices(QUAD_INDEX_COUNT);
  for (int i = 0; i < QUAD_INDEX_COUNT; i += 6) {
    unsigned short base = (unsigned short)(i / 6 * 4);
    quad_indices[i] = base;
    quad_indices[i + 1] = base + 1;
    quad_indices[i + 2] = base + 2;
    quad_indices[i + 3] = base + 2;
    quad_indices[i + 4] = base + 3;
    quad_indices[i + 5] = base;
  }
  glBindBuffer(GL_ELEMENT_ARRAY_BUFFER, quad_index_buffer);
  glBufferData(GL_ELEMENT_ARRAY_BUFFER, (GLsizeiptr)quad_indices.size() * sizeof(unsigned short),
               quad_indices.data(), GL_STATIC_DRAW);
  glBindBuffer(GL_ARRAY_BUFFER, vertex_buffer);
  glEnableVertexAttribArray(0);
  glVertexAttribPointer(0, 4, GL_FLOAT, GL_FALSE, 28, (void *)0);
  glEnableVertexAttribArray(1);
  glVertexAttribPointer(1, 4, GL_UNSIGNED_BYTE, GL_TRUE, 28, (void *)16);
  glEnableVertexAttribArray(2);
  glVertexAttribPointer(2, 2, GL_FLOAT, GL_FALSE, 28, (void *)20);
  glGenBuffers(1, &center_buffer);
  glBindBuffer(GL_ARRAY_BUFFER, center_buffer);
  glVertexAttribPointer(3, 2, GL_FLOAT, GL_FALSE, 8, (void *)0);
  glGenSamplers(STAGES, samplers);

  // An identity ramp until the device sets one.
  unsigned char identity[256 * 4];
  for (int i = 0; i < 256; ++i)
    identity[i * 4] = identity[i * 4 + 1] = identity[i * 4 + 2] = (unsigned char)i, identity[i * 4 + 3] = 255;
  const unsigned char white[4] = {255, 255, 255, 255};
  glGenTextures(1, &blank_texture);
  glBindTexture(GL_TEXTURE_2D, blank_texture);
  glTexImage2D(GL_TEXTURE_2D, 0, GL_RGBA8, 1, 1, 0, GL_RGBA, GL_UNSIGNED_BYTE, white);
  glGenTextures(1, &ice_texture);
  glBindTexture(GL_TEXTURE_2D, ice_texture);
  glTexImage2D(GL_TEXTURE_2D, 0, GL_RGBA8, ICE_SURFACE_WIDTH, ICE_SURFACE_HEIGHT, 0, GL_RGBA, GL_UNSIGNED_BYTE, ice_surface);
  glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_LINEAR);
  glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_S, GL_CLAMP_TO_EDGE);
  glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_T, GL_CLAMP_TO_EDGE);
  glGenTextures(1, &gamma_texture);
  glBindTexture(GL_TEXTURE_2D, gamma_texture);
  glTexImage2D(GL_TEXTURE_2D, 0, GL_RGBA8, 256, 1, 0, GL_RGBA, GL_UNSIGNED_BYTE, identity);
  glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_NEAREST);
  glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_NEAREST);
  glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_S, GL_CLAMP_TO_EDGE);

  // Direct3D 8's defaults.
  render_states[RS_SRCBLEND] = 2;
  render_states[RS_DESTBLEND] = 1;
  render_states[RS_CULLMODE] = 3;
  render_states[RS_ALPHAFUNC] = 8;
  render_states[RS_COLORWRITEENABLE] = 0xf;
  render_states[RS_BLENDOP] = 1;
  render_states[RS_TEXTUREFACTOR] = 0xffffffff;
  for (int s = 0; s < STAGES; ++s) {
    stage_states[s][TSS_COLOROP] = s == 0 ? 4 : 1;
    stage_states[s][TSS_COLORARG1] = 2;
    stage_states[s][TSS_COLORARG2] = 1;
    stage_states[s][TSS_ALPHAOP] = s == 0 ? 2 : 1;
    stage_states[s][TSS_ALPHAARG1] = 2;
    stage_states[s][TSS_ALPHAARG2] = 1;
    stage_states[s][TSS_ADDRESSU] = stage_states[s][TSS_ADDRESSV] = 1;
    stage_states[s][TSS_MAGFILTER] = stage_states[s][TSS_MINFILTER] = 1;
  }
}

Viewport GL_ENTRY(renderer_viewport)(int window_width, int window_height) {
  Target &back = textures[0];
  if (window_width <= 0 || window_height <= 0 || back.logical_width <= 0 || back.logical_height <= 0)
    return {};
  double scale = fmin((double)window_width / back.logical_width, (double)window_height / back.logical_height);
  int width = (int)fmax(1, round(back.logical_width * scale));
  int height = (int)fmax(1, round(back.logical_height * scale));
  return {(window_width - width) / 2, (window_height - height) / 2, width, height,
          back.logical_width, back.logical_height};
}

void GL_ENTRY(renderer_resize)(int window_width, int window_height) {
  drawable_width = window_width;
  drawable_height = window_height;
  Viewport v = GL_ENTRY(renderer_viewport)(window_width, window_height);
  Target &back = textures[0];
  // A minimized window can have no drawable pixels. Keep its last image.
  if (!v.width || !back.framebuffer || (back.width == v.width && back.height == v.height))
    return;
  // Some frames only draw overlays (paused, seeking or waiting for co-op).
  reallocate(back, v.width, v.height, back.flags);
  bind_target();
}

void GL_ENTRY(renderer_present)(int window_width, int window_height) {
  flush_ground_stamps();
  gpu_mark("present");
  Target &back = textures[0];
  if (!back.texture)
    return;
  Viewport v = GL_ENTRY(renderer_viewport)(window_width, window_height);
  if (!v.width)
    return;
  glBindFramebuffer(GL_FRAMEBUFFER, 0);
  glViewport(0, 0, window_width, window_height);
  glColorMask(GL_TRUE, GL_TRUE, GL_TRUE, GL_TRUE);
  glDisable(GL_BLEND);
  glDisable(GL_CULL_FACE);
  glClearColor(0, 0, 0, 1);
  glClear(GL_COLOR_BUFFER_BIT);
  glViewport(v.x, window_height - v.y - v.height, v.width, v.height);
  use_program(present_program);
  glActiveTexture(GL_TEXTURE1);
  glBindTexture(GL_TEXTURE_2D, gamma_texture);
  glActiveTexture(GL_TEXTURE0);
  glBindTexture(GL_TEXTURE_2D, back.texture);
  glBindSampler(0, 0);
  glBindSampler(1, 0);
  // Normally a one-to-one copy; a resize between draw and present may scale once.
  bool exact = v.width == back.width && v.height == back.height;
  glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, exact ? GL_NEAREST : GL_LINEAR);
  glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, exact ? GL_NEAREST : GL_LINEAR);
  glDrawArrays(GL_TRIANGLE_STRIP, 0, 4);
  glBindTexture(GL_TEXTURE_2D, 0);
  // The host swaps next (renderer_frame_end follows it).
  gpu_mark("swap");
}

// A target's bytes, by its format.
static double target_bytes(const Target &t) {
  return (double)t.width * t.height * (t.flags & TARGET_FLOAT ? 16 : t.flags & TARGET_HALF_FLOAT ? 8 : 4);
}
// The frame has been swapped: its record, and those of earlier frames whose
// GPU work has finished.
void GL_ENTRY(renderer_frame_end)() {
  if (!profiling || gpu_frame.empty())
    return gpu_mark("frame");
  if (gpu_timed)
    glEndQuery(GL_TIME_ELAPSED);
  double end = profile_now();
  std::string draws, scene;
  char entry[192];
  for (const auto &[key, count] : draw_frame) {
    snprintf(entry, sizeof entry, "%s%s:[%.0f,%.0f]", draws.empty() ? "" : ",", json_string(key).c_str(), count.quads,
             count.pixels);
    draws += entry;
  }
  for (const auto &[key, value] : profile_scene) {
    snprintf(entry, sizeof entry, "%s\"%s\":%g", scene.empty() ? "" : ",", key.c_str(), value);
    scene += entry;
  }
  double bytes = target_bytes(hdr);
  for (const auto &[id, t] : textures)
    bytes += target_bytes(t);
  const Target &back = textures[0];
  snprintf(entry, sizeof entry,
           ",\"targets\":{\"back\":[%d,%d],\"world\":[%d,%d],\"count\":%zu,\"mb\":%.1f}", back.width,
           back.height, rtx ? hdr.width : back.width, rtx ? hdr.height : back.height, textures.size(), bytes / (1 << 20));
  profile_cpu = "\"cpu\":" + pass_times(gpu_frame, [&](size_t i) {
                  return (i + 1 < gpu_frame.size() ? gpu_frame[i + 1].cpu_at : end) - gpu_frame[i].cpu_at;
                }) + ",\"timed\":" + (gpu_timed ? "true" : "false") + ",\"draws\":{" + draws + "},\"scene\":{" + scene + "}" + entry;
  profile_cpu_ready = true;
  profile_cpu_timed = gpu_timed;
  ++profile_frames;
  draw_frame.clear();
  profile_scene.clear();
  gpu_resume_label = nullptr;
  // Earlier timed frames are read only after a timed one, which reading them
  // perturbs no further: queries finish in order, so a frame whose last has is
  // done.
  if (gpu_timed)
    gpu_pending.push_back({profile_frames - 1, std::move(gpu_frame)});
  while (gpu_timed && !gpu_pending.empty()) {
    PendingFrame &f = gpu_pending.front();
    GLuint available = 0;
    glGetQueryObjectuiv(f.timers.back().query, GL_QUERY_RESULT_AVAILABLE, &available);
    if (!available && gpu_pending.size() <= PROFILE_PENDING)
      break;
    std::vector<double> ms(f.timers.size());
    for (size_t i = 0; i < f.timers.size(); ++i) {
      GLuint64 ns = 0;
      glGetQueryObjectui64v(f.timers[i].query, GL_QUERY_RESULT, &ns);
      ms[i] = ns / 1e6;
      gpu_queries.push_back(f.timers[i].query);
    }
    profile_gpu.emplace_back(f.frame, pass_times(f.timers, [&](size_t i) { return ms[i]; }));
    gpu_pending.pop_front();
  }
  gpu_frame.clear();
  gpu_timed = gpu_every && profile_frames % gpu_every == 0;
  gpu_mark("frame");
}
// The last frame's record (its CPU passes, draws, scene and targets), once.
bool GL_ENTRY(renderer_profile_frame)(long long &frame, std::string &record, bool &timed) {
  if (!profile_cpu_ready)
    return false;
  profile_cpu_ready = false;
  frame = profile_frames - 1;
  record = profile_cpu;
  timed = profile_cpu_timed;
  return true;
}
// A finished frame's GPU passes, oldest first.
bool GL_ENTRY(renderer_profile_gpu)(long long &frame, std::string &passes) {
  if (profile_gpu.empty())
    return false;
  frame = profile_gpu.front().first;
  passes = std::move(profile_gpu.front().second);
  profile_gpu.pop_front();
  return true;
}

void GL_ENTRY(renderer_resume)() { bind_target(); }

bool GL_ENTRY(renderer_set_rtx)(bool enabled) {
#ifdef __EMSCRIPTEN__
  // WebGL2 has no extended-range output: the browser stays classic.
  enabled = false;
#endif
  if (enabled && !tonemap_program) {
    tonemap_program = link(tonemap_vertex_source, tonemap_fragment_source);
    use_program(tonemap_program);
    glUniform1i(uniform_location(tonemap_program, "texture0"), 0);
    glUniform4f(uniform_location(tonemap_program, "colDiffuse"), 1, 1, 1, 1);
    u_tonemap_headroom = uniform_location(tonemap_program, "u_edr_headroom");
    beam_program = link(beam_vertex_source, beam_fragment_source);
    use_program(beam_program);
    glUniform4f(uniform_location(beam_program, "colDiffuse"), 1, 1, 1, 1);
    u_beam_target_size = uniform_location(beam_program, "target_size");
    u_beam_length = uniform_location(beam_program, "beam_length");
    u_beam_step = uniform_location(beam_program, "beam_step");
    u_beam_color = uniform_location(beam_program, "beam_color");
    u_beam_in_world = uniform_location(beam_program, "u_in_world");
    effect_program = link(SHADER_HEADER SHADER_EFFECT_VERT, SHADER_HEADER RTX_SHADER_EFFECT_FRAG);
    use_program(effect_program);
    glUniform4f(uniform_location(effect_program, "colDiffuse"), 1, 1, 1, 1);
    u_effect_target_size = uniform_location(effect_program, "target_size");
    u_effect_kind = uniform_location(effect_program, "u_kind");
    u_effect_params = uniform_location(effect_program, "u_params");
    u_effect_in_world = uniform_location(effect_program, "u_in_world");
    create_lit(creature_lit, creature_lit_vertex_source, creature_fragment_source);
    create_lit(player_lit, lit_vertex_source, player_fragment_source);
    create_lit(bonus_lit, lit_vertex_source, bonus_fragment_source);
    heat_body_program = link(lit_vertex_source, heat_body_fragment_source);
    use_program(heat_body_program);
    glUniform1i(uniform_location(heat_body_program, "texture0"), 0);
    glUniform1i(uniform_location(heat_body_program, "u_density"), 1);
    heat_stamp_program = link(lit_vertex_source, heat_stamp_fragment_source);
    contact_glow_program = link(lit_vertex_source, contact_glow_fragment_source);
    heat_trail_program = link(lit_vertex_source, heat_trail_fragment_source);
    use_program(heat_trail_program);
    glUniform1i(uniform_location(heat_trail_program, "u_heat"), 0);
    pressure_program = link(tonemap_vertex_source, pressure_fragment_source);
    ground_program = link(lit_vertex_source, ground_fragment_source);
    ground_beam_vis_program = link(SHADER_HEADER SHADER_GROUND_VISIBILITY_VERT, ground_beam_vis_source);
    stamp_program = link(lit_vertex_source, stamp_fragment_source);
    use_program(stamp_program);
    glUniform1i(uniform_location(stamp_program, "texture0"), 0);
    u_stamp_target_size = uniform_location(stamp_program, "target_size");
    u_stamp_kind = uniform_location(stamp_program, "u_kind");
    u_stamp_pass = uniform_location(stamp_program, "u_pass");
    u_stamp_wetness = uniform_location(stamp_program, "u_wetness");
    smoke_solver_program = link(smoke_rect_source, smoke_solver_source);
    smoke_splat_program = link(smoke_rect_source, smoke_splat_source);
    smoke_impulse_program = link(smoke_rect_source, smoke_impulse_source);
    smoke_program = link(smoke_field_source, smoke_fragment_source);
    blit_program = link(tonemap_vertex_source, blit_fragment_source);
    use_program(blit_program);
    glUniform1i(uniform_location(blit_program, "source"), 0);
    fill_program = link(tonemap_vertex_source, stamp_fragment_source);
    use_program(fill_program);
    glUniform1i(uniform_location(fill_program, "texture0"), 0);
    u_fill_kind = uniform_location(fill_program, "u_kind");
    u_fill_pass = uniform_location(fill_program, "u_pass");
    u_fill_wetness = uniform_location(fill_program, "u_wetness");
    glGenVertexArrays(1, &beam_array);
    glBindVertexArray(beam_array);
    glGenBuffers(1, &beam_buffer);
    glBindBuffer(GL_ARRAY_BUFFER, beam_buffer);
    glEnableVertexAttribArray(0);
    glVertexAttribPointer(0, 4, GL_FLOAT, GL_FALSE, 16, (void *)0);
  }
  rtx = enabled;
  world = false;
  visibility_dirty = true;
  ground_visibility = {};
  release(hdr);
  // Classic bakes leave the ground's companions behind: RTX makes them afresh.
  while (!grounds.empty())
    drop_ground(grounds.begin()->first);
  for (Target &t : smoke_targets)
    release(t);
  release(smoke_composite);
  release(heat_trail);
  glDeleteFramebuffers(1, &beam_vis_framebuffer);
  glDeleteTextures(1, &beam_vis_texture);
  beam_vis_framebuffer = beam_vis_texture = 0;
  heat_seconds = -1;
  release(pressured);
  release(discarded);
  // Classic keeps an 8-bit back buffer: its draws saturate at white one by one.
  Target &back = textures[0];
  int flags = enabled ? back.flags | TARGET_HALF_FLOAT : back.flags & ~TARGET_HALF_FLOAT;
  if (back.framebuffer && flags != back.flags)
    reallocate(back, back.width, back.height, flags);
  else
    back.flags = flags;
  bind_target();
  return enabled;
}

void GL_ENTRY(renderer_set_headroom)(float headroom) { edr_headroom = headroom; }

// The kept frame (host_frame_hold): the back buffer copied aside, and back.
Target held, anchor;

// The back buffer as top-down RGBA rows.
std::vector<unsigned char> GL_ENTRY(renderer_capture)(int &width, int &height) {
  Target &back = textures[0];
  width = back.width;
  height = back.height;
  std::vector<unsigned char> pixels((size_t)width * height * 4);
  glBindFramebuffer(GL_FRAMEBUFFER, back.framebuffer);
  glReadPixels(0, 0, width, height, GL_RGBA, GL_UNSIGNED_BYTE, pixels.data());
  bind_target();
  return pixels;
}

// --- The game module's host interface ---------------------------------------------

extern "C" {
void GL_ENTRY(w2c_host_frame_hold)(struct w2c_host *, u32 op) {
  if (op == 5) { // HOST_FRAME_ANCHOR_DROP
    release(anchor);
    anchor = {};
    return;
  }
  gpu_aside("hold");
  struct Resume {
    ~Resume() { gpu_resume(); }
  } resume;
  Target &back = textures[0];
  if (!back.framebuffer)
    return;
  Target &from = op == 1 ? back : op == 4 ? anchor : held;
  Target &to = op == 1 || op == 4 ? held : op == 3 ? anchor : back;
  if (!from.framebuffer)
    return;
  // Saved images retain their capture density. Restoring must never shrink the
  // current back buffer or discard its X8R8G8B8 (opaque alpha) semantics.
  if (&to != &back && (to.width != from.width || to.height != from.height || !to.framebuffer)) {
    release(to);
    to.width = from.width;
    to.height = from.height;
    to.logical_width = from.logical_width;
    to.logical_height = from.logical_height;
    to.flags = from.flags;
    allocate(to);
  }
  glBindFramebuffer(GL_READ_FRAMEBUFFER, from.framebuffer);
  glBindFramebuffer(GL_DRAW_FRAMEBUFFER, to.framebuffer);
  glBlitFramebuffer(0, 0, from.width, from.height, 0, 0, to.width, to.height, GL_COLOR_BUFFER_BIT,
                    to.width == from.width && to.height == from.height ? GL_NEAREST : GL_LINEAR);
  bind_target();
}
// The render target `id`, made like `from` unless it already is.
static Target &target_like(int id, const Target &from) {
  drop_ground(id);
  Target &to = textures[id];
  if (to.width != from.width || to.height != from.height || !to.framebuffer) {
    release(to);
    to.width = from.width;
    to.height = from.height;
    to.logical_width = from.logical_width;
    to.logical_height = from.logical_height;
    to.flags = 1;
    allocate(to);
  }
  return to;
}
void GL_ENTRY(w2c_host_texture_copy)(struct w2c_host *, u32 destination, u32 source) {
  Target &from = target_or_back((int)source);
  if (!from.framebuffer)
    return;
  Target &to = target_like((int)destination, from);
  glBindFramebuffer(GL_READ_FRAMEBUFFER, from.framebuffer);
  glBindFramebuffer(GL_DRAW_FRAMEBUFFER, to.framebuffer);
  glBlitFramebuffer(0, 0, from.width, from.height, 0, 0, from.width, from.height, GL_COLOR_BUFFER_BIT, GL_NEAREST);
  bind_target();
}
u32 GL_ENTRY(w2c_host_texture_read)(struct w2c_host *, u32 id, u32 out, u32 capacity) {
  const Target &t = textures[(int)id];
  u32 size = (u32)t.width * t.height * 4;
  if (!t.framebuffer || capacity < size)
    return t.framebuffer ? size : 0;
  glBindFramebuffer(GL_READ_FRAMEBUFFER, t.framebuffer);
  glReadPixels(0, 0, t.width, t.height, GL_RGBA, GL_UNSIGNED_BYTE, client_memory() + out);
  bind_target();
  return size;
}
u32 GL_ENTRY(w2c_host_texture_write)(struct w2c_host *, u32 id, u32 like, u32 pixels, u32 size) {
  const Target &from = textures[(int)like];
  if (!from.framebuffer || size != (u32)from.width * from.height * 4)
    return 0;
  Target &to = target_like((int)id, from);
  glBindTexture(GL_TEXTURE_2D, to.texture);
  glTexSubImage2D(GL_TEXTURE_2D, 0, 0, 0, to.width, to.height, GL_RGBA, GL_UNSIGNED_BYTE, client_memory() + pixels);
  return 1;
}
void GL_ENTRY(w2c_host_back_buffer)(struct w2c_host *, u32 width, u32 height) {
  Target &back = textures[0];
  release(back);
  back.logical_width = (int)width;
  back.logical_height = (int)height;
  Viewport v = GL_ENTRY(renderer_viewport)(drawable_width, drawable_height);
  back.width = v.width ? v.width : (int)width;
  back.height = v.height ? v.height : (int)height;
  back.flags = 1 | 2 | (rtx ? TARGET_HALF_FLOAT : 0); // the back buffer is X8R8G8B8
  allocate(back);
  current_target = 0;
  bind_target();
}
void GL_ENTRY(w2c_host_texture_create)(struct w2c_host *, u32 id, u32 width, u32 height, u32 flags) {
  Target &t = textures[(int)id];
  release(t);
  t.logical_width = t.width = (int)width;
  t.logical_height = t.height = (int)height;
  t.flags = (int)flags;
  // The game's offscreen render target is its persistent ground. Rasterize it
  // at 2x the configured density, independently of the window. Uploaded artwork
  // keeps its source dimensions; replay copies inherit the allocated size.
  if (t.flags & 1) {
    t.width *= 2;
    t.height *= 2;
  }
  allocate(t);
  bind_target();
}
void GL_ENTRY(w2c_host_texture_upload)(struct w2c_host *, u32 id, u32 texels) {
  auto it = textures.find((int)id);
  if (it == textures.end())
    return;
  Target &t = it->second;
  if (!(t.flags & TARGET_RENDER))
    texel_addresses[(int)id] = texels;
  // A8R8G8B8 texels are BGRA bytes.
  std::vector<unsigned char> rgba((size_t)t.width * t.height * 4);
  const u8 *bgra = client_memory() + texels;
  // LockRect supplies logical-sized CPU storage, even for a denser GPU target.
  // Replicate uploaded texels there; reading physical dimensions from the
  // module would run beyond its source buffer.
  for (int y = 0; y < t.height; ++y)
    for (int x = 0; x < t.width; ++x) {
      size_t source = ((size_t)(y * t.logical_height / t.height) * t.logical_width +
                       x * t.logical_width / t.width) * 4;
      size_t destination = ((size_t)y * t.width + x) * 4;
      rgba[destination] = bgra[source + 2];
      rgba[destination + 1] = bgra[source + 1];
      rgba[destination + 2] = bgra[source];
      rgba[destination + 3] = bgra[source + 3];
    }
  glBindTexture(GL_TEXTURE_2D, t.texture);
  glTexSubImage2D(GL_TEXTURE_2D, 0, 0, 0, t.width, t.height, GL_RGBA, GL_UNSIGNED_BYTE, rgba.data());
}
void GL_ENTRY(w2c_host_texture_release)(struct w2c_host *, u32 id) {
  auto it = textures.find((int)id);
  if (it == textures.end() || !id)
    return;
  if (current_target == (int)id)
    current_target = 0;
  drop_ground((int)id);
  release(it->second);
  textures.erase(it);
  texel_addresses.erase((int)id);
  for (auto *maps : {&thickness_maps, &heat_density_maps}) {
    auto map = maps->find((int)id);
    if (map != maps->end()) {
      glDeleteTextures(1, &map->second);
      maps->erase(map);
    }
  }
  bind_target();
}
void GL_ENTRY(w2c_host_render_state)(struct w2c_host *, u32 state, u32 value) {
  if (state < 256)
    render_states[state] = value;
}
void GL_ENTRY(w2c_host_texture_stage_state)(struct w2c_host *, u32 stage, u32 state, u32 value) {
  if (stage < STAGES && state < 32)
    stage_states[stage][state] = value;
}
void GL_ENTRY(w2c_host_set_texture)(struct w2c_host *, u32 stage, u32 id) {
  if (stage < STAGES)
    bound[stage] = (int)id;
}
void GL_ENTRY(w2c_host_set_render_target)(struct w2c_host *, u32 id) {
  flush_ground_stamps();
  current_target = (int)id;
  if (id)
    gpu_aside("bake");
  else
    gpu_resume();
  bind_target();
}
void GL_ENTRY(w2c_host_clear)(struct w2c_host *, u32 color) {
  drop_ground(current_target);
  bind_target();
  Target &t = drawing_target(current_target);
  glColorMask(GL_TRUE, GL_TRUE, GL_TRUE, GL_TRUE);
  glClearColor((color >> 16 & 255) / 255.0f, (color >> 8 & 255) / 255.0f, (color & 255) / 255.0f,
               t.flags & 2 ? 1.0f : (color >> 24) / 255.0f);
  glClear(GL_COLOR_BUFFER_BIT);
}
// The circle the device shades itself (host_circle), or none: classic.frag's circle and circle_uv.
static float circle[8];
// A draw through the device's own shading into the bound target `t`.
static void device_draw(const Target &t, u32 primitive, const void *vertices, u32 vertex_count,
                        const unsigned short *indices, u32 primitive_count) {
  use_program(program);
  ClassicUniforms &c = classic_uniforms;
  const float size[] = {(float)t.logical_width, (float)t.logical_height};
  if (c.target_size.change(size))
    glUniform2fv(u_target_size, 1, size);
  GLint has[STAGES], cop[STAGES], ca1[STAGES], ca2[STAGES], aop[STAGES], aa1[STAGES], aa2[STAGES], filters[STAGES];
  for (int s = 0; s < STAGES; ++s) {
    auto it = textures.find(bound[s]);
    bool present = bound[s] && it != textures.end() && it->second.texture;
    has[s] = present;
    bool artwork = present && !(it->second.flags & 1);
    filters[s] = artwork && stage_states[s][TSS_MINFILTER] >= 2 && stage_states[s][TSS_MAGFILTER] >= 2 ? 1 : 0;
    if (artwork && current_target && stage_states[s][TSS_TERRAIN_ART])
      filters[s] = 2;
    cop[s] = (GLint)stage_states[s][TSS_COLOROP];
    ca1[s] = (GLint)stage_states[s][TSS_COLORARG1];
    ca2[s] = (GLint)stage_states[s][TSS_COLORARG2];
    aop[s] = (GLint)stage_states[s][TSS_ALPHAOP];
    aa1[s] = (GLint)stage_states[s][TSS_ALPHAARG1];
    aa2[s] = (GLint)stage_states[s][TSS_ALPHAARG2];
    glActiveTexture(GL_TEXTURE0 + s);
    glBindTexture(GL_TEXTURE_2D, present ? it->second.texture : blank_texture);
    glBindSampler(s, samplers[s]);
    apply_sampler(s, stage_states[s]);
  }
  glActiveTexture(GL_TEXTURE0);
  if (c.has_texture.change(has))
    glUniform2iv(u_has_texture, 1, has);
  if (c.reconstruction.change(filters))
    glUniform2iv(u_reconstruction, 1, filters);
  if (c.color_op.change(cop))
    glUniform2iv(u_color_op, 1, cop);
  if (c.color_arg1.change(ca1))
    glUniform2iv(u_color_arg1, 1, ca1);
  if (c.color_arg2.change(ca2))
    glUniform2iv(u_color_arg2, 1, ca2);
  if (c.alpha_op.change(aop))
    glUniform2iv(u_alpha_op, 1, aop);
  if (c.alpha_arg1.change(aa1))
    glUniform2iv(u_alpha_arg1, 1, aa1);
  if (c.alpha_arg2.change(aa2))
    glUniform2iv(u_alpha_arg2, 1, aa2);
  unsigned f = render_states[RS_TEXTUREFACTOR];
  const float factor[] = {(f >> 16 & 255) / 255.0f, (f >> 8 & 255) / 255.0f,
                          (f & 255) / 255.0f, (f >> 24) / 255.0f};
  GLint alpha_test = render_states[RS_ALPHATESTENABLE] != 0 && !(in_world(t) && additive_emission(render_states));
  float alpha_ref = (float)(render_states[RS_ALPHAREF] & 255);
  GLint alpha_func = (GLint)render_states[RS_ALPHAFUNC];
  if (c.factor.change(factor)) glUniform4fv(u_factor, 1, factor);
  if (c.alpha_test.change(alpha_test)) glUniform1i(u_alpha_test, alpha_test);
  if (c.alpha_ref.change(alpha_ref)) glUniform1f(u_alpha_ref, alpha_ref);
  if (c.alpha_func.change(alpha_func)) glUniform1i(u_alpha_func, alpha_func);
  GLint world_light = in_world(t);
  if (c.in_world.change(world_light)) glUniform1i(u_in_world, world_light);
  GLint glint = world_light && material == HOST_PASS_GLINT;
  if (c.glint.change(glint)) glUniform1i(u_glint, glint);
  // `circle + 4` is a pointer; preserve the four actual values in each cache.
  const float circle_rect[] = {circle[0], circle[1], circle[2], circle[3]};
  const float circle_uv[] = {circle[4], circle[5], circle[6], circle[7]};
  if (c.circle.change(circle_rect)) glUniform4fv(u_circle, 1, circle_rect);
  if (c.circle_uv.change(circle_uv)) glUniform4fv(u_circle_uv, 1, circle_uv);

  apply_output_state(t);
  unsigned cull = render_states[RS_CULLMODE];
  if (cull == 2 || cull == 3) {
    glEnable(GL_CULL_FACE);
    glFrontFace(GL_CCW);
    glCullFace(cull == 3 ? GL_BACK : GL_FRONT);
  } else {
    glDisable(GL_CULL_FACE);
  }
  submit_geometry(primitive, vertices, vertex_count, indices, primitive_count);
}
// A bake's marked decal draws reach the terrain's companions pass by pass, as
// materials.py stamps them: every substrate draw, then every coverage stamp,
// then the surface's two passes, each target bound once and its draws in the
// bake's order. Each draw keeps its own device states, decal texture and
// material. The queue empties as the bake's marks end, and before anything
// reads, replaces or rescales the companions.
struct GroundStamp {
  int kind;
  float seconds;
  u32 primitive, vertex_count, primitive_count;
  size_t vertex_at, index_at; // in ground_stamp_bytes; index_at SIZE_MAX for none
  unsigned render_states[256], stage_states[STAGES][32];
  int bound[STAGES];
};
std::vector<GroundStamp> ground_stamps;
std::vector<unsigned char> ground_stamp_bytes;
int ground_stamp_target;

void queue_ground_stamp(Ground &g, u32 primitive, const void *vertices, u32 vertex_count,
                        const unsigned short *indices, u32 primitive_count) {
  if (ground_stamp_target != current_target)
    flush_ground_stamps();
  // The surface's wetness rebases onto a later epoch between the stamps before it and the ones after.
  if (ground_kind != HOST_GROUND_DECAL && ground_seconds - g.epoch > 180) {
    flush_ground_stamps();
    rebase_wetness(g, ground_seconds);
    // The bake's next draws go to the terrain again.
    bind_target();
  }
  ground_stamp_target = current_target;
  GroundStamp s;
  s.kind = ground_kind, s.seconds = ground_seconds;
  s.primitive = primitive, s.vertex_count = vertex_count, s.primitive_count = primitive_count;
  const unsigned char *v = (const unsigned char *)vertices;
  s.vertex_at = ground_stamp_bytes.size();
  ground_stamp_bytes.insert(ground_stamp_bytes.end(), v, v + (size_t)vertex_count * 28);
  s.index_at = SIZE_MAX;
  if (indices) {
    const unsigned char *i = (const unsigned char *)indices;
    s.index_at = ground_stamp_bytes.size();
    ground_stamp_bytes.insert(ground_stamp_bytes.end(), i, i + (size_t)index_count(primitive, primitive_count) * 2);
  }
  memcpy(s.render_states, render_states, sizeof render_states);
  memcpy(s.stage_states, stage_states, sizeof stage_states);
  memcpy(s.bound, bound, sizeof bound);
  ground_stamps.push_back(s);
}

void discard_ground_stamps(int id) {
  if (ground_stamp_target == id) {
    ground_stamps.clear();
    ground_stamp_bytes.clear();
  }
}

void flush_ground_stamps() {
  if (ground_stamps.empty())
    return;
  auto found = grounds.find(ground_stamp_target);
  Ground &g = found->second;
  auto vertices = [](const GroundStamp &s) { return ground_stamp_bytes.data() + s.vertex_at; };
  auto indices = [](const GroundStamp &s) {
    return s.index_at == SIZE_MAX ? nullptr : (const unsigned short *)(ground_stamp_bytes.data() + s.index_at);
  };
  // The substrate takes every draw but blood's, through the device's own shading as it was set for the draw.
  unsigned saved_states[256], saved_stages[STAGES][32];
  int saved_bound[STAGES];
  memcpy(saved_states, render_states, sizeof render_states);
  memcpy(saved_stages, stage_states, sizeof stage_states);
  memcpy(saved_bound, bound, sizeof bound);
  int saved_target = current_target;
  current_target = ground_stamp_target;
  bind_framebuffer(g.substrate);
  for (const GroundStamp &s : ground_stamps) {
    if (s.kind == HOST_GROUND_BLOOD)
      continue;
    memcpy(render_states, s.render_states, sizeof render_states);
    memcpy(stage_states, s.stage_states, sizeof stage_states);
    memcpy(bound, s.bound, sizeof bound);
    device_draw(g.substrate, s.primitive, vertices(s), s.vertex_count, indices(s), s.primitive_count);
  }
  memcpy(render_states, saved_states, sizeof render_states);
  memcpy(stage_states, saved_stages, sizeof stage_states);
  memcpy(bound, saved_bound, sizeof bound);
  current_target = saved_target;
  // Each material's coverage, then specularity, wetness and volume, then
  // height (materials.py's _stamp_commands), each with its own blend and channels.
  use_program(stamp_program);
  glUniform2f(u_stamp_target_size, (float)g.surface.logical_width, (float)g.surface.logical_height);
  glDisable(GL_CULL_FACE);
  glEnable(GL_BLEND);
  glBlendEquation(GL_FUNC_ADD);
  glActiveTexture(GL_TEXTURE0);
  for (int pass = 0; pass < 3; ++pass) {
    bind_framebuffer(pass ? g.surface : g.coverage);
    glUniform1i(u_stamp_pass, pass);
    for (const GroundStamp &s : ground_stamps) {
      if (s.kind == HOST_GROUND_DECAL || (pass == 2 && s.kind == HOST_GROUND_BLOOD))
        continue;
      glUniform1i(u_stamp_kind, s.kind);
      glUniform1f(u_stamp_wetness, expf((s.seconds - g.epoch) / 45));
      auto it = textures.find(s.bound[0]);
      bool present = s.bound[0] && it != textures.end() && it->second.texture;
      glBindTexture(GL_TEXTURE_2D, present ? it->second.texture : blank_texture);
      glBindSampler(0, samplers[0]);
      // The decal samples as the device's stage 0 was set for its draw.
      apply_sampler(0, s.stage_states[0]);
      if (pass == 0) {
        // RGB weighs the materials alpha-over; A is ice coverage, which every later material occludes.
        glColorMask(GL_TRUE, GL_TRUE, GL_TRUE, GL_TRUE);
        glBlendFuncSeparate(GL_SRC_ALPHA, GL_ONE_MINUS_SRC_ALPHA, s.kind == HOST_GROUND_ICE ? GL_ONE : GL_ZERO,
                            GL_ONE_MINUS_SRC_ALPHA);
      } else if (pass == 1) {
        glColorMask(s.kind != HOST_GROUND_BLOOD, GL_TRUE, GL_TRUE, GL_FALSE);
        glBlendFunc(s.kind == HOST_GROUND_BLOOD ? GL_ONE : GL_SRC_ALPHA, GL_ONE_MINUS_SRC_ALPHA);
      } else {
        glColorMask(GL_FALSE, GL_FALSE, GL_FALSE, GL_TRUE);
        glBlendFunc(GL_ONE, GL_ONE_MINUS_SRC_ALPHA);
      }
      submit_geometry(s.primitive, vertices(s), s.vertex_count, indices(s), s.primitive_count);
    }
  }
  ground_stamps.clear();
  ground_stamp_bytes.clear();
  bind_target();
}

void GL_ENTRY(w2c_host_draw)(struct w2c_host *, u32 primitive, u32 vertices, u32 vertex_count, u32 indices,
                   u32 primitive_count) {
  if (profiling) {
    auto texture = textures.find(bound[0]);
    count_draw(bound[0] && texture != textures.end()
                   ? "tex" + std::to_string(bound[0]) + "-" + std::to_string(texture->second.logical_width) + "x" +
                         std::to_string(texture->second.logical_height)
                   : "untextured",
               (const float *)(client_memory() + vertices), 7,
               indices ? (const unsigned short *)(client_memory() + indices) : nullptr, (int)primitive,
               primitive >= 4 && primitive <= 6 ? (int)primitive_count : 0);
  }
  if (rtx && world && material == HOST_PASS_GROUND ? ground_draw(primitive, vertices, vertex_count, indices, primitive_count)
                                                   : lit_draw(primitive, vertices, vertex_count, indices, primitive_count))
    return;
  Target &t = drawing_target(current_target);
  // A marked decal reaches the ground's companions too: the substrate unless it
  // is blood, the materials if it has one, queued for the bake's end.
  bool marked = rtx && ground_kind != HOST_GROUND_END && current_target && (t.flags & TARGET_RENDER);
  Ground *g = marked ? &ground_of(current_target) : nullptr;
  const void *data = client_memory() + vertices;
  const unsigned short *index_data = indices ? (const unsigned short *)(client_memory() + indices) : nullptr;
  device_draw(t, primitive, data, vertex_count, index_data, primitive_count);
  if (g)
    queue_ground_stamp(*g, primitive, data, vertex_count, index_data, primitive_count);
}
void GL_ENTRY(w2c_host_circle)(struct w2c_host *, u32 shape, u32 color) {
  EffectVertex vertices[4];
  circle_quad((const float *)(client_memory() + shape), color, vertices, circle);
  device_draw(drawing_target(current_target), 6, vertices, 4, nullptr, 2);
  memset(circle, 0, sizeof(circle));
}
static void upload_analytic_vertices(GLuint array, GLuint buffer,
                                     const void *data, size_t bytes,
                                     GLenum primitive, int count) {
  glBindVertexArray(array);
  glBindBuffer(GL_ARRAY_BUFFER, buffer);
  glBufferData(GL_ARRAY_BUFFER, bytes, data, GL_STREAM_DRAW);
  glDrawArrays(primitive, 0, count);
}
void GL_ENTRY(w2c_host_beam)(struct w2c_host *, u32 corners, f32 length, f32 step, u32 color) {
  profile_stat("beams", 1);
  if (!rtx)
    return;
  Target &t = drawing_target(current_target);
  use_program(beam_program);
  glUniform2f(u_beam_target_size, (float)t.logical_width, (float)t.logical_height);
  glUniform1f(u_beam_length, length);
  glUniform1f(u_beam_step, step);
  glUniform4f(u_beam_color, (color >> 16 & 255) / 255.0f, (color >> 8 & 255) / 255.0f, (color & 255) / 255.0f,
              (color >> 24) / 255.0f);
  glUniform1i(u_beam_in_world, in_world(t));
  apply_output_state(t);
  // A flat quad, whichever way its corners turn.
  glDisable(GL_CULL_FACE);
  count_draw("beam", (const float *)(client_memory() + corners), 4, nullptr, 6, 2);
  upload_analytic_vertices(beam_array, beam_buffer, client_memory() + corners,
                           16 * sizeof(float), GL_TRIANGLE_FAN, 4);
}
// Radial sprite batches and parameterized single effects share the device
// vertex layout.
static void draw_effect_vertices(const EffectVertex *vertices, int count,
                                 int kind, const float *params) {
  count_draw("effect" + std::to_string(kind), (const float *)vertices, 7, nullptr, 4, count / 3);
  Target &t = drawing_target(current_target);
  use_program(effect_program);
  glUniform2f(u_effect_target_size, (float)t.logical_width,
              (float)t.logical_height);
  glUniform1i(u_effect_kind, kind);
  glUniform4fv(u_effect_params, 3, params);
  glUniform1i(u_effect_in_world, in_world(t));
  apply_output_state(t);
  glDisable(GL_CULL_FACE);
  upload_analytic_vertices(vertex_array, vertex_buffer, vertices,
                           count * sizeof(EffectVertex), GL_TRIANGLES, count);
}
void GL_ENTRY(w2c_host_effect)(struct w2c_host *, u32 corners, u32 kind,
                               u32 params, u32 color) {
  if (!rtx)
    return;
  EffectVertex vertices[6];
  effect_quad((const float *)(client_memory() + corners), color, vertices);
  draw_effect_vertices(vertices, 6, kind,
                       (const float *)(client_memory() + params));
}
void GL_ENTRY(w2c_host_effect_sprites)(struct w2c_host *, u32 vertices,
                                       u32 kind, u32 count) {
  profile_stat("effect_vertices", count);
  if (!rtx)
    return;
  const float params[12] = {};
  draw_effect_vertices((const EffectVertex *)(client_memory() + vertices),
                       count, kind, params);
}
void GL_ENTRY(w2c_host_scene)(struct w2c_host *, u32 view, u32 lights, u32 count) {
  visibility_dirty = true;
  profile_stat("lights", count);
  const float *v = (const float *)(client_memory() + view);
  scene_camera[0] = v[0], scene_camera[1] = v[1], scene_seconds = v[2];
  ground_size[0] = v[3], ground_size[1] = v[4];
  memcpy(beam_gain, v + 5, sizeof beam_gain);
  scene_debug = (int)v[7];
  light_count = (int)count < MAX_LIGHTS ? (int)count : MAX_LIGHTS;
  beam_lights = false;
  for (int i = 0; i < light_count; ++i) {
    const float *l = (const float *)(client_memory() + lights) + i * RTX_LIGHT_FLOATS;
    memcpy(light_pos + i * 4, l, 16);
    memcpy(light_rgb + i * 4, l + 4, 16);
    memcpy(light_dir + i * 4, l + 8, 16);
    light_dir[i * 4 + 2] = l[16]; // creatures, players and bonuses weight a segment by its tail
    memcpy(light_response + i * 4, l + 12, 16);
    memcpy(ground_dir + i * 4, l + 8, 16);
    ground_dir[i * 4 + 2] = l[17];
    light_tail[i] = l[16];
    memcpy(beam_shape + i * 4, l + 20, 16);
    beam_lights |= l[23] > 0;
    profile_stat("beam_lights", l[23] > 0);
  }
}
void GL_ENTRY(w2c_host_pressure)(struct w2c_host *, u32 fronts, u32 count) {
  profile_stat("pressure_fronts", count);
  const float *f = (const float *)(client_memory() + fronts);
  pressure_fronts.assign(f, f + count * 4);
}
// The frame's footprints into the trail buffer (heat_vision.py's update): fade
// it by the run's clock since the last frame, or start it over after a rewind,
// a long gap or a new terrain, then keep each footprint's warmth where higher.
void GL_ENTRY(w2c_host_heat)(struct w2c_host *, u32 footprints, u32 count) {
  profile_stat("heat_footprints", count);
  if (!rtx || (!count && !heat_trail.framebuffer))
    return;
  gpu_aside("heat-stamp");
  struct Resume {
    ~Resume() { gpu_resume(); }
  } resume;
  int width = std::max(1, (int)lroundf(ground_size[0] * HEAT_TRAIL_SCALE));
  int height = std::max(1, (int)lroundf(ground_size[1] * HEAT_TRAIL_SCALE));
  if (heat_trail.width != width || heat_trail.height != height) {
    release(heat_trail);
    heat_trail.width = heat_trail.logical_width = width, heat_trail.height = heat_trail.logical_height = height;
    heat_trail.flags = TARGET_RENDER | TARGET_HALF_FLOAT;
    allocate(heat_trail);
    heat_seconds = -1;
  }
  float gap = heat_seconds < 0 ? -1 : scene_seconds - heat_seconds;
  heat_seconds = scene_seconds;
  bind_framebuffer(heat_trail);
  glColorMask(GL_TRUE, GL_TRUE, GL_TRUE, GL_TRUE);
  glDisable(GL_CULL_FACE);
  GLuint p = heat_stamp_program;
  use_program(p);
  glUniform2f(uniform_location(p, "target_size"), (float)width, (float)height);
  glUniform2f(uniform_location(p, "camera"), 0, 0);
  auto quad = [](std::vector<HostVertex> &v, float x0, float y0, float x1, float y1, u32 color) {
    auto corner = [&](float x, float y, float u, float w) { return HostVertex{x, y, 0, 1, color, u, w}; };
    for (HostVertex c : {corner(x0, y0, 0, 0), corner(x0, y1, 0, 1), corner(x1, y1, 1, 1), corner(x0, y0, 0, 0),
                         corner(x1, y1, 1, 1), corner(x1, y0, 1, 0)})
      v.push_back(c);
  };
  if (gap < 0 || gap > HEAT_MAX_GAP_S) {
    glClearColor(0, 0, 0, 0);
    glClear(GL_COLOR_BUFFER_BIT);
  } else if (gap > 0) {
    glUniform1f(uniform_location(p, "u_fade"), 1 - powf(0.5f, gap / HEAT_HALF_LIFE_S));
    glEnable(GL_BLEND);
    glBlendEquation(GL_FUNC_ADD);
    glBlendFunc(GL_ZERO, GL_ONE_MINUS_SRC_ALPHA);
    std::vector<HostVertex> whole;
    quad(whole, 0, 0, (float)width, (float)height, 0xffffffff);
    submit_vertices(whole);
  }
  std::vector<HostVertex> stamps;
  const float *f = (const float *)(client_memory() + footprints);
  for (u32 i = 0; i < count; ++i, f += 4) {
    float x = f[0] * HEAT_TRAIL_SCALE, y = f[1] * HEAT_TRAIL_SCALE, r = f[2] * HEAT_TRAIL_SCALE;
    quad(stamps, x - r, y - r, x + r, y + r, (u32)(std::min(1.0f, f[3]) * 255 + 0.5f) << 24 | 0xffffff);
  }
  if (!stamps.empty()) {
    glUniform1f(uniform_location(p, "u_fade"), -1);
    glEnable(GL_BLEND);
    glBlendEquation(GL_MAX);
    glBlendFunc(GL_ONE, GL_ONE);
    submit_vertices(stamps);
  }
  bind_target();
}
// The trail buffer added to the ground in view, before the creatures' overlays.
void GL_ENTRY(w2c_host_heat_trails)(struct w2c_host *, f32 alpha) {
  if (!rtx || !world || !heat_trail.texture)
    return;
  gpu_mark("heat");
  Target &t = drawing_target(current_target);
  GLuint p = heat_trail_program;
  use_program(p);
  glUniform2f(uniform_location(p, "target_size"), (float)t.logical_width, (float)t.logical_height);
  glUniform2f(uniform_location(p, "camera"), scene_camera[0], scene_camera[1]);
  glUniform2fv(uniform_location(p, "u_ground_size"), 1, ground_size);
  glUniform1f(uniform_location(p, "u_alpha"), alpha);
  glActiveTexture(GL_TEXTURE0);
  glBindTexture(GL_TEXTURE_2D, heat_trail.texture);
  glBindSampler(0, 0);
  glEnable(GL_BLEND);
  glBlendEquation(GL_FUNC_ADD);
  glBlendFunc(GL_ONE, GL_ONE);
  glColorMask(GL_TRUE, GL_TRUE, GL_TRUE, GL_TRUE);
  glDisable(GL_CULL_FACE);
  float w = (float)t.logical_width, h = (float)t.logical_height;
  submit_vertices({{0, 0, 0, 1, 0xffffffff, 0, 0}, {0, h, 0, 1, 0xffffffff, 0, 0}, {w, h, 0, 1, 0xffffffff, 0, 0},
                   {0, 0, 0, 1, 0xffffffff, 0, 0}, {w, h, 0, 1, 0xffffffff, 0, 0}, {w, 0, 0, 1, 0xffffffff, 0, 0}});
}
void GL_ENTRY(w2c_host_ground)(struct w2c_host *, u32 kind, f32 seconds) {
  if (kind == HOST_GROUND_END)
    flush_ground_stamps();
  ground_kind = (int)kind;
  ground_seconds = seconds;
}
void GL_ENTRY(w2c_host_smoke)(struct w2c_host *, u32 commands, u32 count) {
  profile_stat("smoke_commands", count);
  if (!rtx)
    return;
  gpu_mark("smoke-solver");
  const float *c = (const float *)(client_memory() + commands), *end = c + count;
  while (c < end) {
    switch ((int)*c) {
    case SMOKE_RESET:
      smoke_resolution = c[1], smoke_world[0] = c[2], smoke_world[1] = c[3], smoke_dt = c[4];
      smoke_iterations = (int)c[5];
      for (int i = 0; i < SMOKE_TARGETS; ++i) {
        Target &t = smoke_targets[i];
        if (t.width != (int)smoke_resolution) {
          release(t);
          t.width = t.height = t.logical_width = t.logical_height = (int)smoke_resolution;
          t.flags = TARGET_RENDER | TARGET_HALF_FLOAT;
          allocate(t);
        }
        clear_smoke_target(i);
      }
      smoke_current = 0;
      c += 6;
      break;
    case SMOKE_FADE:
      smoke_fade = c[1];
      smoke_pass(1 - smoke_current, smoke_current, 5);
      smoke_current = 1 - smoke_current;
      c += 2;
      break;
    case SMOKE_SPLAT: {
      GLuint p = smoke_splat_program;
      use_program(p);
      glUniform4fv(uniform_location(p, "u_source"), 1, c + 5);
      glUniform4fv(uniform_location(p, "u_motion"), 1, c + 9);
      glUniform1f(uniform_location(p, "u_rotation"), c[13]);
      glUniform4fv(uniform_location(p, "u_flow"), 1, c + 14);
      smoke_add(p, c + 1);
      c += 18;
      break;
    }
    case SMOKE_IMPULSE: {
      GLuint p = smoke_impulse_program;
      use_program(p);
      glUniform4fv(uniform_location(p, "u_segment"), 1, c + 5);
      glUniform4fv(uniform_location(p, "u_impulse"), 1, c + 9);
      glUniform4fv(uniform_location(p, "u_phase"), 1, c + 13);
      smoke_add(p, c + 1);
      c += 17;
      break;
    }
    case SMOKE_PROJECT: {
      // Advect velocity, take its divergence, relax pressure, then subtract its gradient.
      int other = 1 - smoke_current;
      smoke_pass(other, smoke_current, 0);
      smoke_pass(2, other, 1);
      clear_smoke_target(3);
      int pressure = 3;
      for (int i = 0; i < smoke_iterations; ++i) {
        smoke_pass(7 - pressure, pressure, 2, 2);
        pressure = 7 - pressure;
      }
      smoke_pass(smoke_current, other, 3, pressure);
      c += 1;
      break;
    }
    case SMOKE_TRANSPORT:
      smoke_decay = c[1];
      smoke_pass(1 - smoke_current, smoke_current, 4);
      smoke_current = 1 - smoke_current;
      c += 2;
      break;
    case SMOKE_DRAG: {
      int count = std::min((int)c[1], 64);
      std::vector<float> paths, motions;
      for (int i = 0; i < count; ++i) {
        paths.insert(paths.end(), c + 2 + i * 8, c + 6 + i * 8);
        motions.insert(motions.end(), c + 6 + i * 8, c + 10 + i * 8);
      }
      GLuint p = smoke_solver_program;
      use_program(p);
      glUniform1i(uniform_location(p, "u_body_count"), count);
      glUniform4fv(uniform_location(p, "u_body_path"), count, paths.data());
      glUniform4fv(uniform_location(p, "u_body_motion"), count, motions.data());
      smoke_pass(1 - smoke_current, smoke_current, 6);
      smoke_current = 1 - smoke_current;
      c += 2 + (int)c[1] * 8;
      break;
    }
    default:
      client_fatal("Unknown smoke command");
    }
  }
  bind_target();
}
void GL_ENTRY(w2c_host_smoke_draw)(struct w2c_host *, u32 view, u32 lights, u32 light_count, u32 sights,
                                   u32 sight_count) {
  profile_stat("smoke_lights", light_count);
  if (!rtx || !world || !smoke_targets[0].texture)
    return;
  gpu_mark("smoke");
  const float *v = (const float *)(client_memory() + view);
  Target &t = drawing_target(current_target);
  // Smoke is a low-frequency volume: integrate it at most 640 pixels across.
  float scale = fminf(1.0f, (float)SMOKE_DISPLAY_MAX_AXIS / (float)std::max(t.width, t.height));
  int width = std::max(1, (int)lroundf(t.width * scale)), height = std::max(1, (int)lroundf(t.height * scale));
  if (smoke_composite.width != width || smoke_composite.height != height) {
    release(smoke_composite);
    smoke_composite.width = width, smoke_composite.height = height;
    smoke_composite.flags = TARGET_RENDER | TARGET_HALF_FLOAT;
    allocate(smoke_composite);
  }
  smoke_composite.logical_width = t.logical_width, smoke_composite.logical_height = t.logical_height;
  bind_framebuffer(smoke_composite);
  glColorMask(GL_TRUE, GL_TRUE, GL_TRUE, GL_TRUE);
  glClearColor(0, 0, 0, 0);
  glClear(GL_COLOR_BUFFER_BIT);
  // Straight RGB becomes premultiplied once; alpha accumulates as alpha.
  glEnable(GL_BLEND);
  glBlendEquation(GL_FUNC_ADD);
  glBlendFuncSeparate(GL_SRC_ALPHA, GL_ONE_MINUS_SRC_ALPHA, GL_ONE, GL_ONE_MINUS_SRC_ALPHA);
  GLuint p = smoke_program;
  use_program(p);
  auto at = [p](const char *name) { return uniform_location(p, name); };
  glUniform4fv(at("rect"), 1, v);
  glUniform2f(at("target_size"), (float)t.logical_width, (float)t.logical_height);
  glUniform1i(at("texture0"), 0);
  glUniform1i(at("u_state_flip"), 1);
  glUniform2fv(at("u_origin"), 1, v + 4);
  glUniform2fv(at("u_size"), 1, v + 6);
  glUniform1f(at("u_opacity"), v[8]);
  glUniform1i(at("u_debug"), scene_debug >= DEBUG_SMOKE ? scene_debug : 0);
  glUniform1i(at("u_light_count"), (int)light_count);
  std::vector<float> pos, rgb, shape, tails((light_count + 3) / 4 * 4);
  const float *l = (const float *)(client_memory() + lights);
  for (u32 i = 0; i < light_count; ++i, l += SMOKE_LIGHT_FLOATS) {
    pos.insert(pos.end(), l, l + 4);
    rgb.insert(rgb.end(), l + 4, l + 8);
    shape.insert(shape.end(), l + 8, l + 12);
    tails[i] = l[12];
  }
  if (light_count) {
    glUniform4fv(at("u_light_pos"), (int)light_count, pos.data());
    glUniform4fv(at("u_light_rgb"), (int)light_count, rgb.data());
    glUniform4fv(at("u_light_shape"), (int)light_count, shape.data());
    glUniform4fv(at("u_light_tail"), (int)(light_count + 3) / 4, tails.data());
  }
  glUniform1i(at("u_sight_count"), (int)sight_count);
  if (sight_count)
    glUniform4fv(at("u_sights"), (int)sight_count, (const float *)(client_memory() + sights));
  glActiveTexture(GL_TEXTURE0);
  glBindTexture(GL_TEXTURE_2D, smoke_targets[smoke_current].texture);
  glBindSampler(0, 0);
  glDisable(GL_CULL_FACE);
  glBindVertexArray(vertex_array);
  glDrawArrays(GL_TRIANGLE_STRIP, 0, 4);
  // The premultiplied composite over the world.
  smoke_drawing = true;
  bind_target();
  use_program(blit_program);
  glBlendFunc(GL_ONE, GL_ONE_MINUS_SRC_ALPHA);
  glColorMask(GL_TRUE, GL_TRUE, GL_TRUE, GL_TRUE);
  glBindTexture(GL_TEXTURE_2D, smoke_composite.texture);
  glDrawArrays(GL_TRIANGLE_STRIP, 0, 4);
  smoke_drawing = false;
  bind_target();
}
void GL_ENTRY(w2c_host_occlusion)(struct w2c_host *, u32 grid, u32 values, u32 count) {
  visibility_dirty = true;
  const float *g = (const float *)(client_memory() + grid);
  occlusion_grid[0] = g[0], occlusion_grid[1] = g[1], occlusion_grid[2] = count ? g[2] : 0, occlusion_grid[3] = g[3];
  occlusion_cell = g[4];
  dynamic_shadows = g[5] != 0;
  profile_stat("occlusion_texels", count / 4.);
  profile_stat("occlusion_cells", count ? g[2] * g[3] : 0);
  if (!count)
    return;
  // Whole rows, and a texture that grows in powers of two as crowds do.
  int rows = (int)((count + OCCLUSION_WIDTH * 4 - 1) / (OCCLUSION_WIDTH * 4));
  int slot = occlusion_next;
  occlusion_next = (occlusion_next + 1) % 3;
  if (rows > occlusion_texture_rows[slot]) {
    int grown = 1;
    while (grown < rows)
      grown *= 2;
    occlusion_texture_rows[slot] = grown;
    if (!occlusion_textures[slot])
      glGenTextures(1, &occlusion_textures[slot]);
    glBindTexture(GL_TEXTURE_2D, occlusion_textures[slot]);
    glTexImage2D(GL_TEXTURE_2D, 0, GL_RGBA32F, OCCLUSION_WIDTH, grown, 0, GL_RGBA, GL_FLOAT, nullptr);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_NEAREST);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_NEAREST);
  }
  occlusion_texture = occlusion_textures[slot];
  occlusion_texels.resize((size_t)rows * OCCLUSION_WIDTH * 4);
  memcpy(occlusion_texels.data(), client_memory() + values, (size_t)count * 4);
  std::fill(occlusion_texels.begin() + count, occlusion_texels.end(), 0.0f);
  glBindTexture(GL_TEXTURE_2D, occlusion_texture);
  glTexSubImage2D(GL_TEXTURE_2D, 0, 0, 0, OCCLUSION_WIDTH, rows, GL_RGBA, GL_FLOAT, occlusion_texels.data());
}
void GL_ENTRY(w2c_host_bonus)(struct w2c_host *, u32 emblem, f32 grid_x, f32 grid_y, f32 center_x, f32 center_y) {
  gpu_mark("bonuses");
  material = MATERIAL_BONUS;
  bonus_emblem = (int)emblem;
  bonus_grid[0] = grid_x, bonus_grid[1] = grid_y;
  bonus_center[0] = center_x, bonus_center[1] = center_y;
}
void GL_ENTRY(w2c_host_render_pass)(struct w2c_host *, u32 pass) {
  static const char *const labels[] = {"", "world", "post", "creatures", "players", "sprites", "ground", "heat"};
  // Classic marks only the world's bounds: what follows is its HUD.
  gpu_mark(!rtx && pass == HOST_PASS_WORLD_END ? "hud" : pass < sizeof labels / sizeof *labels ? labels[pass] : "sprites");
  if (pass >= HOST_PASS_CREATURES) {
    material = pass == HOST_PASS_SPRITES ? 0 : (int)pass;
    if (world && debug_map()) // in or out of the ground's map
      bind_target();
    return;
  }
  Target &back = textures[0];
  if (!rtx || !back.framebuffer)
    return;
  if (pass == HOST_PASS_WORLD_BEGIN) { // Scene/occlusion inputs have arrived; shade masks before HDR.
    profile_stat("worlds", 1); // more than one before a present is drawing nobody sees
    prepare_ground_visibility(back.logical_width, back.logical_height);
    int width = back.width, height = back.height;
    world_size(back.logical_width, width, height);
    if (hdr.width != width || hdr.height != height || !hdr.framebuffer) {
      release(hdr);
      hdr.width = width;
      hdr.height = height;
      hdr.flags = back.flags | TARGET_HALF_FLOAT;
      allocate(hdr);
    }
    hdr.logical_width = back.logical_width;
    hdr.logical_height = back.logical_height;
    if (debug_map() && (discarded.width != width || discarded.height != height || !discarded.framebuffer)) {
      release(discarded);
      discarded.width = width, discarded.height = height, discarded.flags = hdr.flags;
      allocate(discarded);
    }
    discarded.logical_width = hdr.logical_width, discarded.logical_height = hdr.logical_height;
    if (scene_debug >= DEBUG_SMOKE) { // the smoke's maps over black
      glBindFramebuffer(GL_FRAMEBUFFER, hdr.framebuffer);
      glColorMask(GL_TRUE, GL_TRUE, GL_TRUE, GL_TRUE);
      glClearColor(0, 0, 0, 1);
      glClear(GL_COLOR_BUFFER_BIT);
    } else {
      glBindFramebuffer(GL_READ_FRAMEBUFFER, back.framebuffer);
      glBindFramebuffer(GL_DRAW_FRAMEBUFFER, hdr.framebuffer);
      glBlitFramebuffer(0, 0, back.width, back.height, 0, 0, hdr.width, hdr.height, GL_COLOR_BUFFER_BIT,
                        hdr.width == back.width ? GL_NEAREST : GL_LINEAR);
    }
    world = true;
  } else if (pass == HOST_PASS_WORLD_END && world) {
    world = false;
    material = 0;
    // What follows the world's post passes is the HUD's.
    struct HudMark {
      ~HudMark() { gpu_mark("hud"); }
    } hud;
    // The pressure fronts displace the world, in its own pixels, into a second target.
    const Target *world_image = &hdr;
    if (!pressure_fronts.empty()) {
      if (pressured.width != hdr.width || pressured.height != hdr.height) {
        release(pressured);
        pressured.width = hdr.width, pressured.height = hdr.height, pressured.flags = hdr.flags;
        allocate(pressured);
      }
      float sx = (float)hdr.width / hdr.logical_width, sy = (float)hdr.height / hdr.logical_height;
      int count = (int)pressure_fronts.size() / 4;
      std::vector<float> fronts, strengths((count + 3) / 4 * 4);
      for (int i = 0; i < count; ++i) {
        const float *f = &pressure_fronts[i * 4];
        fronts.insert(fronts.end(), {f[0] * sx, f[1] * sy, f[2] * sx, f[2] * sy});
        strengths[i] = f[3];
      }
      bind_framebuffer(pressured);
      use_program(pressure_program);
      glUniform1i(uniform_location(pressure_program, "texture0"), 0);
      glUniform2f(uniform_location(pressure_program, "u_size"), (float)hdr.width, (float)hdr.height);
      glUniform1i(uniform_location(pressure_program, "u_count"), count);
      glUniform4fv(uniform_location(pressure_program, "u_fronts"), count, fronts.data());
      glUniform4fv(uniform_location(pressure_program, "u_strength"), (count + 3) / 4, strengths.data());
      glDisable(GL_BLEND);
      glDisable(GL_CULL_FACE);
      glColorMask(GL_TRUE, GL_TRUE, GL_TRUE, GL_TRUE);
      glActiveTexture(GL_TEXTURE0);
      glBindTexture(GL_TEXTURE_2D, hdr.texture);
      glBindSampler(0, 0);
      glBindVertexArray(vertex_array);
      glDrawArrays(GL_TRIANGLE_STRIP, 0, 4);
      world_image = &pressured;
    }
    // A world drawn smaller (render_size) scales up as it tonemaps; a debug
    // map's values go to the display as they are.
    glBindFramebuffer(GL_FRAMEBUFFER, back.framebuffer);
    glViewport(0, 0, back.width, back.height);
    if (debug_map()) {
      use_program(blit_program);
    } else {
      use_program(tonemap_program);
      glUniform1f(u_tonemap_headroom, edr_headroom);
    }
    glDisable(GL_BLEND);
    glDisable(GL_CULL_FACE);
    glColorMask(GL_TRUE, GL_TRUE, GL_TRUE, GL_TRUE);
    glActiveTexture(GL_TEXTURE0);
    glBindTexture(GL_TEXTURE_2D, world_image->texture);
    glBindSampler(0, 0);
    glBindVertexArray(vertex_array);
    glDrawArrays(GL_TRIANGLE_STRIP, 0, 4);
  }
  bind_target();
}
void GL_ENTRY(w2c_host_gamma_ramp)(struct w2c_host *, u32 red, u32 green, u32 blue) {
  // D3DGAMMARAMP: three tables of 256 16-bit levels.
  unsigned char ramp[256 * 4];
  const u8 *m = client_memory();
  for (int i = 0; i < 256; ++i) {
    unsigned short r, g, b;
    memcpy(&r, m + red + i * 2, 2);
    memcpy(&g, m + green + i * 2, 2);
    memcpy(&b, m + blue + i * 2, 2);
    ramp[i * 4] = (unsigned char)(r >> 8);
    ramp[i * 4 + 1] = (unsigned char)(g >> 8);
    ramp[i * 4 + 2] = (unsigned char)(b >> 8);
    ramp[i * 4 + 3] = 255;
  }
  glBindTexture(GL_TEXTURE_2D, gamma_texture);
  glTexSubImage2D(GL_TEXTURE_2D, 0, 0, 0, 256, 1, GL_RGBA, GL_UNSIGNED_BYTE, ramp);
}
}
