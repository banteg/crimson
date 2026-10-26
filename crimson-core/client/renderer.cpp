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
#include <algorithm>
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

namespace {

// CRIMSON_GPU_TIMERS: GPU time per pass. Each mark ends the running query and
// starts one charged to its label; a frame's queries are read at the next
// present, by when they have finished. WebGL2 has no timer queries.
struct GpuTimer {
  const char *label;
  GLuint query;
};
#ifdef __EMSCRIPTEN__
const bool gpu_timers = false;
#define GL_TIME_ELAPSED 0
#define glGetQueryObjectui64v(query, name, value)
#else
const bool gpu_timers = getenv("CRIMSON_GPU_TIMERS");
#endif
std::vector<GpuTimer> gpu_frame, gpu_previous;
std::vector<GLuint> gpu_queries;
std::string gpu_timings;
// With the timers, each pass's draws by texture (or analytic kind) and target:
// quads, and the target pixels they cover, read a frame late with the timings.
struct DrawCount {
  double quads = 0, pixels = 0;
};
std::map<std::string, DrawCount> draw_frame, draw_previous;
std::string draw_stats;
void gpu_mark(const char *label) {
  if (!gpu_timers || (!gpu_frame.empty() && !strcmp(gpu_frame.back().label, label)))
    return;
  if (!gpu_frame.empty())
    glEndQuery(GL_TIME_ELAPSED);
  GLuint query;
  if (gpu_queries.empty()) {
    glGenQueries(1, &query);
  } else {
    query = gpu_queries.back();
    gpu_queries.pop_back();
  }
  glBeginQuery(GL_TIME_ELAPSED, query);
  gpu_frame.push_back({label, query});
}
// Drawing off the back buffer outside the world's passes (terrain decal bakes,
// heat stamps) gets its own timer, so the `frame` timer keeps only the
// simulation's time; the label before it resumes after.
const char *gpu_resume_label;
void gpu_aside(const char *label) {
  if (!gpu_timers || gpu_resume_label)
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
// The frame ends: read the one before it, then start the next.
void gpu_frame_end() {
  if (!gpu_timers || gpu_frame.empty())
    return;
  glEndQuery(GL_TIME_ELAPSED);
  std::vector<std::pair<const char *, double>> totals;
  for (const GpuTimer &t : gpu_previous) {
    GLuint64 ns = 0;
    glGetQueryObjectui64v(t.query, GL_QUERY_RESULT, &ns);
    auto it = std::find_if(totals.begin(), totals.end(), [&](const auto &p) { return !strcmp(p.first, t.label); });
    (it == totals.end() ? totals.emplace_back(t.label, 0.0) : *it).second += ns / 1e6;
    gpu_queries.push_back(t.query);
  }
  gpu_timings.clear();
  char entry[160];
  for (const auto &[label, ms] : totals) {
    snprintf(entry, sizeof entry, "%s%s=%.3f", gpu_timings.empty() ? "" : " ", label, ms);
    gpu_timings += entry;
  }
  gpu_previous.swap(gpu_frame);
  gpu_frame.clear();
  gpu_resume_label = nullptr;
  draw_stats.clear();
  for (const auto &[key, count] : draw_previous) {
    snprintf(entry, sizeof entry, "%s%s=%.0f/%.0f", draw_stats.empty() ? "" : " ", key.c_str(), count.quads, count.pixels);
    draw_stats += entry;
  }
  draw_previous.swap(draw_frame);
  draw_frame.clear();
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
GLuint program, present_program, vertex_array, vertex_buffer, index_buffer, samplers[STAGES], gamma_texture;
// Bound to a stage with no texture: the shader never samples it, but a sampler
// needs a complete texture behind it.
GLuint blank_texture;
GLint u_target_size, u_has_texture, u_color_op, u_color_arg1, u_color_arg2, u_alpha_op, u_alpha_arg1, u_alpha_arg2,
    u_factor, u_alpha_test, u_alpha_ref, u_alpha_func, u_reconstruction;
// RTX: the world's HDR target while the world draws (host_render_pass), and the
// tonemap that puts it on the back buffer toward the display's EDR headroom.
bool rtx, world;
Target hdr;
GLuint tonemap_program, beam_program, beam_array, beam_buffer;
GLuint effect_program;
GLint u_effect_target_size, u_effect_kind, u_effect_params;
GLint u_tonemap_headroom, u_beam_target_size, u_beam_length, u_beam_step, u_beam_color;
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
  GLint pass, grid, shell_center;
};
// The creature body grid (host_occlusion): origin, columns (0 for none) and rows,
// cell size, the shadows setting, and its texels in an RGBA32F texture 256 wide.
enum { OCCLUSION_WIDTH = 256 };
float occlusion_grid[4], occlusion_cell = 64;
int dynamic_shadows, occlusion_rows;
GLuint occlusion_texture;
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
// The beams' visibility at a quarter of the ground's resolution (ground.frag's
// BEAM_VISIBILITY_PASS): four groups of four slots side by side in one atlas,
// which the ground reads instead of walking the body grid per pixel.
enum { BEAM_VISIBILITY_SCALE = 4, BEAM_VISIBILITY_SLOTS = 16 };
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

// Where a draw lands: while the RTX world draws, the back buffer's draws go to
// the HDR target.
Target &drawing_target(int id) {
  Target &t = target_or_back(id);
  return world && &t == &textures[0] ? hdr : t;
}

// Counts a draw for the timers: `what` it draws, its triangles as corner
// indices into x, y positions `stride` floats apart (the current target's
// logical units), `primitive` a device primitive (4 list, 5 strip, 6 fan).
void count_draw(const std::string &what, const float *positions, int stride, const unsigned short *indices,
                int primitive, int triangles) {
  if (!gpu_timers || primitive < 4 || primitive > 6)
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

void create_lit(LitProgram &p, const char *fragment) {
  p.id = link(lit_vertex_source, fragment);
  glUseProgram(p.id);
  glUniform1i(glGetUniformLocation(p.id, "texture0"), 0);
  glUniform1i(glGetUniformLocation(p.id, "u_thickness"), 1);
  glUniform1i(glGetUniformLocation(p.id, "u_occlusion_tex"), 2);
  glUniform4f(glGetUniformLocation(p.id, "colDiffuse"), 1, 1, 1, 1);
  p.target_size = glGetUniformLocation(p.id, "target_size");
  p.camera = glGetUniformLocation(p.id, "camera");
  p.count = glGetUniformLocation(p.id, "u_count");
  p.ambient = glGetUniformLocation(p.id, "u_ambient");
  p.pos = glGetUniformLocation(p.id, "u_pos");
  p.rgb = glGetUniformLocation(p.id, "u_rgb");
  p.dir = glGetUniformLocation(p.id, "u_dir");
  p.response = glGetUniformLocation(p.id, "u_response");
  p.occlusion_grid = glGetUniformLocation(p.id, "u_occlusion_grid");
  p.occlusion_cell = glGetUniformLocation(p.id, "u_occlusion_cell_size");
  p.shadows = glGetUniformLocation(p.id, "u_dynamic_shadows");
  p.pass = glGetUniformLocation(p.id, "u_pass");
  p.grid = glGetUniformLocation(p.id, "u_grid");
  p.shell_center = glGetUniformLocation(p.id, "u_shell_center");
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
void submit_geometry(u32 primitive, u32 vertices, u32 vertex_count, u32 indices, u32 primitive_count) {
  static const GLenum modes[] = {GL_POINTS, GL_POINTS, GL_LINES, GL_LINE_STRIP, GL_TRIANGLES, GL_TRIANGLE_STRIP, GL_TRIANGLE_FAN};
  GLenum mode = primitive < 7 ? modes[primitive] : GL_TRIANGLES;
  glBindVertexArray(vertex_array);
  glBindBuffer(GL_ARRAY_BUFFER, vertex_buffer);
  glBufferData(GL_ARRAY_BUFFER, (GLsizeiptr)vertex_count * 28, client_memory() + vertices, GL_STREAM_DRAW);
  int index_count = primitive == 4 ? primitive_count * 3 : primitive == 5 || primitive == 6 ? primitive_count + 2
                    : primitive == 2 ? primitive_count * 2 : primitive == 3 ? primitive_count + 1 : primitive_count;
  if (indices) {
    glBindBuffer(GL_ELEMENT_ARRAY_BUFFER, index_buffer);
    glBufferData(GL_ELEMENT_ARRAY_BUFFER, (GLsizeiptr)index_count * 2, client_memory() + indices, GL_STREAM_DRAW);
    glDrawElements(mode, index_count, GL_UNSIGNED_SHORT, nullptr);
  } else {
    glDrawArrays(mode, 0, index_count);
  }
}

// A creature batch drawn again as heat (heat_body.frag): the atlas and its
// smooth silhouette density, blended as the device's states say.
bool heat_draw(Target &t, u32 primitive, u32 vertices, u32 vertex_count, u32 indices, u32 primitive_count) {
  glUseProgram(heat_body_program);
  glUniform2f(glGetUniformLocation(heat_body_program, "target_size"), (float)t.logical_width, (float)t.logical_height);
  glUniform2f(glGetUniformLocation(heat_body_program, "camera"), scene_camera[0], scene_camera[1]);
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
  glUseProgram(contact_glow_program);
  glUniform2f(glGetUniformLocation(contact_glow_program, "target_size"), (float)t.logical_width, (float)t.logical_height);
  glUniform2f(glGetUniformLocation(contact_glow_program, "camera"), scene_camera[0], scene_camera[1]);
  apply_output_state(t);
  glDisable(GL_CULL_FACE);
  submit_geometry(primitive, vertices, vertex_count, indices, primitive_count);
  return true;
}

// A draw in an RTX creature, player or bonus batch, lit as the Python port
// lights them: creatures (their ambient fill is 0.6) and bonuses always, players
// only under lights.
bool lit_draw(u32 primitive, u32 vertices, u32 vertex_count, u32 indices, u32 primitive_count) {
  if (!rtx || !world || !material || material == HOST_PASS_GROUND || (material == HOST_PASS_PLAYERS && !light_count))
    return false;
  Target &t = drawing_target(current_target);
  if (material == HOST_PASS_HEAT)
    return heat_draw(t, primitive, vertices, vertex_count, indices, primitive_count);
  if (material == HOST_PASS_GLOW)
    return glow_draw(t, primitive, vertices, vertex_count, indices, primitive_count);
  LitProgram &p = material == HOST_PASS_PLAYERS ? player_lit
                  : material == MATERIAL_BONUS  ? bonus_lit
                                                : creature_lit;
  glUseProgram(p.id);
  glUniform1i(p.pass, bonus_emblem);
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
  glSamplerParameteri(samplers[0], GL_TEXTURE_WRAP_S, address(stage_states[0][TSS_ADDRESSU]));
  glSamplerParameteri(samplers[0], GL_TEXTURE_WRAP_T, address(stage_states[0][TSS_ADDRESSV]));
  glSamplerParameteri(samplers[0], GL_TEXTURE_MAG_FILTER, stage_states[0][TSS_MAGFILTER] >= 2 ? GL_LINEAR : GL_NEAREST);
  glSamplerParameteri(samplers[0], GL_TEXTURE_MIN_FILTER, stage_states[0][TSS_MINFILTER] >= 2 ? GL_LINEAR : GL_NEAREST);
  glActiveTexture(GL_TEXTURE1);
  glBindTexture(GL_TEXTURE_2D, material == HOST_PASS_CREATURES && present ? shape_map(bound[0]) : blank_texture);
  glBindSampler(1, 0);
  glActiveTexture(GL_TEXTURE2);
  glBindTexture(GL_TEXTURE_2D, occlusion_grid[2] ? occlusion_texture : blank_texture);
  glBindSampler(2, 0);
  glActiveTexture(GL_TEXTURE0);
  apply_output_state(t);
  glDisable(GL_CULL_FACE);
  submit_geometry(primitive, vertices, vertex_count, indices, primitive_count);
  return true;
}

// A ground pass over a whole companion: the stamp shader's `kind` and `pass`
// over `source`, into the bound framebuffer.
void ground_fill(GLuint source, int kind, int pass, float wetness) {
  glUseProgram(fill_program);
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

// A marked decal draw's material stamps (materials.py's _stamp_commands, one
// draw at a time): its coverage, then specularity, wetness and volume, then
// height, each with its own blend and channels.
void stamp_ground(Ground &g, int kind, u32 primitive, u32 vertices, u32 vertex_count, u32 indices,
                  u32 primitive_count) {
  if (ground_seconds - g.epoch > 180)
    rebase_wetness(g, ground_seconds);
  glUseProgram(stamp_program);
  glUniform2f(u_stamp_target_size, (float)g.surface.logical_width, (float)g.surface.logical_height);
  glUniform1i(u_stamp_kind, kind);
  glUniform1f(u_stamp_wetness, expf((ground_seconds - g.epoch) / 45));
  auto it = textures.find(bound[0]);
  bool present = bound[0] && it != textures.end() && it->second.texture;
  glActiveTexture(GL_TEXTURE0);
  glBindTexture(GL_TEXTURE_2D, present ? it->second.texture : blank_texture);
  glBindSampler(0, samplers[0]);
  glDisable(GL_CULL_FACE);
  glEnable(GL_BLEND);
  glBlendEquation(GL_FUNC_ADD);
  for (int pass = 0; pass < 3; ++pass) {
    if (pass == 2 && kind == HOST_GROUND_BLOOD)
      break;
    bind_framebuffer(pass ? g.surface : g.coverage);
    glUniform1i(u_stamp_pass, pass);
    if (pass == 0) {
      // RGB weighs the materials alpha-over; A is ice coverage, which every later material occludes.
      glColorMask(GL_TRUE, GL_TRUE, GL_TRUE, GL_TRUE);
      glBlendFuncSeparate(GL_SRC_ALPHA, GL_ONE_MINUS_SRC_ALPHA, kind == HOST_GROUND_ICE ? GL_ONE : GL_ZERO,
                          GL_ONE_MINUS_SRC_ALPHA);
    } else if (pass == 1) {
      glColorMask(kind != HOST_GROUND_BLOOD, GL_TRUE, GL_TRUE, GL_FALSE);
      glBlendFunc(kind == HOST_GROUND_BLOOD ? GL_ONE : GL_SRC_ALPHA, GL_ONE_MINUS_SRC_ALPHA);
    } else {
      glColorMask(GL_FALSE, GL_FALSE, GL_FALSE, GL_TRUE);
      glBlendFunc(GL_ONE, GL_ONE_MINUS_SRC_ALPHA);
    }
    submit_geometry(primitive, vertices, vertex_count, indices, primitive_count);
  }
}

// A rect of a smoke target through one of the solver's programs, its uniforms set.
void smoke_rect(GLuint p, const float *rect) {
  glUniform4fv(glGetUniformLocation(p, "rect"), 1, rect);
  glUniform2f(glGetUniformLocation(p, "u_resolution"), smoke_resolution, smoke_resolution);
  glUniform2fv(glGetUniformLocation(p, "u_world_size"), 1, smoke_world);
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
  glUseProgram(p);
  glUniform1i(glGetUniformLocation(p, "texture0"), 0);
  glUniform1i(glGetUniformLocation(p, "u_aux"), 1);
  glUniform1i(glGetUniformLocation(p, "u_mode"), mode);
  glUniform1f(glGetUniformLocation(p, "u_dt"), smoke_dt);
  glUniform1f(glGetUniformLocation(p, "u_decay"), smoke_decay);
  glUniform1f(glGetUniformLocation(p, "u_fade"), smoke_fade);
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

// The terrain drawn into the world, lit as the Python port's ground: its
// substrate, materials and surface under the frame's lights and body shadows.
bool ground_draw(u32 primitive, u32 vertices, u32 vertex_count, u32 indices, u32 primitive_count) {
  auto it = textures.find(bound[0]);
  if (!bound[0] || it == textures.end() || !it->second.framebuffer)
    return false;
  Ground &g = ground_of(bound[0]);
  Target &t = drawing_target(current_target);
  // Lit beams take the slots in light order; the rest walk the grid in the ground's own pass.
  float slots[MAX_LIGHTS] = {};
  int count = 0;
  if (beam_lights && dynamic_shadows && occlusion_grid[2])
    for (int i = 0; i < light_count && count < BEAM_VISIBILITY_SLOTS; ++i)
      if (beam_shape[i * 4 + 3] > 0)
        slots[i] = (float)++count;
  auto prepare = [&](GLuint p) {
    glUseProgram(p);
    auto at = [p](const char *name) { return glGetUniformLocation(p, name); };
    glUniform2f(at("target_size"), (float)t.logical_width, (float)t.logical_height);
    glUniform2f(at("camera"), scene_camera[0], scene_camera[1]);
    glUniform2fv(at("u_ground_size"), 1, ground_size);
    glUniform1f(at("u_time_s"), scene_seconds - g.epoch);
    glUniform1i(at("u_debug"), 0);
    glUniform1i(at("u_debug_display"), 1);
    glUniform1i(at("u_dynamic_shadows"), dynamic_shadows);
    glUniform1i(at("u_spec_light_count"), light_count);
    glUniform1i(at("u_has_beam_lights"), beam_lights);
    glUniform2fv(at("u_beam_gain"), 1, beam_gain);
    glUniform4fv(at("u_occlusion_grid"), 1, occlusion_grid);
    glUniform1f(at("u_occlusion_cell_size"), occlusion_cell);
    if (light_count) {
      glUniform4fv(at("u_spec_pos"), light_count, light_pos);
      glUniform4fv(at("u_spec_color"), light_count, light_rgb);
      glUniform4fv(at("u_spec_dir"), light_count, ground_dir);
      glUniform4fv(at("u_spec_response"), light_count, light_response);
      glUniform4fv(at("u_spec_tail"), (light_count + 3) / 4, light_tail);
      glUniform4fv(at("u_beam_shape"), light_count, beam_shape);
      glUniform4fv(at("u_beam_slots"), (light_count + 3) / 4, slots);
    }
    const GLuint inputs[] = {g.substrate.texture, g.surface.texture, g.coverage.texture,
                             occlusion_grid[2] ? occlusion_texture : blank_texture,
                             count ? beam_vis_texture : blank_texture};
    const char *names[] = {"u_substrate_tex", "u_surface_tex", "u_material_tex", "u_occlusion_tex", "u_beam_vis"};
    for (int i = 0; i < 5; ++i) {
      glUniform1i(at(names[i]), i);
      glActiveTexture(GL_TEXTURE0 + i);
      glBindTexture(GL_TEXTURE_2D, inputs[i]);
      glBindSampler(i, 0);
    }
    glActiveTexture(GL_TEXTURE0);
  };
  if (count) {
    int width = std::max(1, t.width / BEAM_VISIBILITY_SCALE), height = std::max(1, t.height / BEAM_VISIBILITY_SCALE);
    if (!beam_vis_framebuffer || width != beam_vis_width || height != beam_vis_height) {
      if (!beam_vis_framebuffer) {
        glGenFramebuffers(1, &beam_vis_framebuffer);
        glGenTextures(1, &beam_vis_texture);
      }
      glBindTexture(GL_TEXTURE_2D, beam_vis_texture);
      glTexImage2D(GL_TEXTURE_2D, 0, GL_RGBA16F, 4 * width, height, 0, GL_RGBA, GL_HALF_FLOAT, nullptr);
      glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_LINEAR);
      glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_LINEAR);
      glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_S, GL_CLAMP_TO_EDGE);
      glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_T, GL_CLAMP_TO_EDGE);
      glBindFramebuffer(GL_FRAMEBUFFER, beam_vis_framebuffer);
      glFramebufferTexture2D(GL_FRAMEBUFFER, GL_COLOR_ATTACHMENT0, GL_TEXTURE_2D, beam_vis_texture, 0);
      beam_vis_width = width, beam_vis_height = height;
    }
    glBindFramebuffer(GL_FRAMEBUFFER, beam_vis_framebuffer);
    glDisable(GL_BLEND);
    glDisable(GL_CULL_FACE);
    glColorMask(GL_TRUE, GL_TRUE, GL_TRUE, GL_TRUE);
    glViewport(0, 0, 4 * width, height);
    glClearColor(1, 1, 1, 1);
    glClear(GL_COLOR_BUFFER_BIT);
    prepare(ground_beam_vis_program);
    GLint group_at = glGetUniformLocation(ground_beam_vis_program, "u_beam_group");
    for (int group = 0; group * 4 < count; ++group) {
      glViewport(group * width, 0, width, height);
      glUniform1f(group_at, (float)group);
      submit_geometry(primitive, vertices, vertex_count, indices, primitive_count);
    }
    bind_target();
  }
  prepare(ground_program);
  if (count)
    glUniform4f(glGetUniformLocation(ground_program, "u_beam_vis_target"), (float)t.width, (float)t.height,
                (float)beam_vis_width, (float)beam_vis_height);
  apply_output_state(t);
  glDisable(GL_BLEND); // the ground is opaque
  glDisable(GL_CULL_FACE);
  submit_geometry(primitive, vertices, vertex_count, indices, primitive_count);
  return true;
}

} // namespace

void GL_ENTRY(renderer_init)() {
  program = link(vertex_source, fragment_source);
  present_program = link(present_vertex_source, present_fragment_source);
  u_target_size = glGetUniformLocation(program, "target_size");
  u_has_texture = glGetUniformLocation(program, "has_texture");
  u_reconstruction = glGetUniformLocation(program, "reconstruction");
  u_color_op = glGetUniformLocation(program, "color_op");
  u_color_arg1 = glGetUniformLocation(program, "color_arg1");
  u_color_arg2 = glGetUniformLocation(program, "color_arg2");
  u_alpha_op = glGetUniformLocation(program, "alpha_op");
  u_alpha_arg1 = glGetUniformLocation(program, "alpha_arg1");
  u_alpha_arg2 = glGetUniformLocation(program, "alpha_arg2");
  u_factor = glGetUniformLocation(program, "factor");
  u_alpha_test = glGetUniformLocation(program, "alpha_test");
  u_alpha_ref = glGetUniformLocation(program, "alpha_ref");
  u_alpha_func = glGetUniformLocation(program, "alpha_func");
  glUseProgram(program);
  glUniform1i(glGetUniformLocation(program, "texture0"), 0);
  glUniform1i(glGetUniformLocation(program, "texture1"), 1);
  glUseProgram(present_program);
  glUniform1i(glGetUniformLocation(present_program, "back_buffer"), 0);
  glUniform1i(glGetUniformLocation(present_program, "gamma"), 1);

  glGenVertexArrays(1, &vertex_array);
  glBindVertexArray(vertex_array);
  glGenBuffers(1, &vertex_buffer);
  glGenBuffers(1, &index_buffer);
  glBindBuffer(GL_ARRAY_BUFFER, vertex_buffer);
  glEnableVertexAttribArray(0);
  glVertexAttribPointer(0, 4, GL_FLOAT, GL_FALSE, 28, (void *)0);
  glEnableVertexAttribArray(1);
  glVertexAttribPointer(1, 4, GL_UNSIGNED_BYTE, GL_TRUE, 28, (void *)16);
  glEnableVertexAttribArray(2);
  glVertexAttribPointer(2, 2, GL_FLOAT, GL_FALSE, 28, (void *)20);
  glGenSamplers(STAGES, samplers);

  // An identity ramp until the device sets one.
  unsigned char identity[256 * 4];
  for (int i = 0; i < 256; ++i)
    identity[i * 4] = identity[i * 4 + 1] = identity[i * 4 + 2] = (unsigned char)i, identity[i * 4 + 3] = 255;
  const unsigned char white[4] = {255, 255, 255, 255};
  glGenTextures(1, &blank_texture);
  glBindTexture(GL_TEXTURE_2D, blank_texture);
  glTexImage2D(GL_TEXTURE_2D, 0, GL_RGBA8, 1, 1, 0, GL_RGBA, GL_UNSIGNED_BYTE, white);
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
  glUseProgram(present_program);
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
  gpu_frame_end();
  gpu_mark("frame");
}

std::string GL_ENTRY(renderer_gpu_timings)() { return gpu_timings; }
std::string GL_ENTRY(renderer_draw_stats)() { return draw_stats; }

void GL_ENTRY(renderer_resume)() { bind_target(); }

bool GL_ENTRY(renderer_set_rtx)(bool enabled) {
#ifdef __EMSCRIPTEN__
  // WebGL2 has no extended-range output: the browser stays classic.
  enabled = false;
#endif
  if (enabled && !tonemap_program) {
    tonemap_program = link(tonemap_vertex_source, tonemap_fragment_source);
    glUseProgram(tonemap_program);
    glUniform1i(glGetUniformLocation(tonemap_program, "texture0"), 0);
    glUniform4f(glGetUniformLocation(tonemap_program, "colDiffuse"), 1, 1, 1, 1);
    u_tonemap_headroom = glGetUniformLocation(tonemap_program, "u_edr_headroom");
    beam_program = link(beam_vertex_source, beam_fragment_source);
    glUseProgram(beam_program);
    glUniform4f(glGetUniformLocation(beam_program, "colDiffuse"), 1, 1, 1, 1);
    u_beam_target_size = glGetUniformLocation(beam_program, "target_size");
    u_beam_length = glGetUniformLocation(beam_program, "beam_length");
    u_beam_step = glGetUniformLocation(beam_program, "beam_step");
    u_beam_color = glGetUniformLocation(beam_program, "beam_color");
    effect_program = link(SHADER_HEADER SHADER_EFFECT_VERT, SHADER_HEADER RTX_SHADER_EFFECT_FRAG);
    glUseProgram(effect_program);
    glUniform4f(glGetUniformLocation(effect_program, "colDiffuse"), 1, 1, 1, 1);
    u_effect_target_size = glGetUniformLocation(effect_program, "target_size");
    u_effect_kind = glGetUniformLocation(effect_program, "u_kind");
    u_effect_params = glGetUniformLocation(effect_program, "u_params");
    create_lit(creature_lit, creature_fragment_source);
    create_lit(player_lit, player_fragment_source);
    create_lit(bonus_lit, bonus_fragment_source);
    heat_body_program = link(lit_vertex_source, heat_body_fragment_source);
    glUseProgram(heat_body_program);
    glUniform1i(glGetUniformLocation(heat_body_program, "texture0"), 0);
    glUniform1i(glGetUniformLocation(heat_body_program, "u_density"), 1);
    heat_stamp_program = link(lit_vertex_source, heat_stamp_fragment_source);
    contact_glow_program = link(lit_vertex_source, contact_glow_fragment_source);
    heat_trail_program = link(lit_vertex_source, heat_trail_fragment_source);
    glUseProgram(heat_trail_program);
    glUniform1i(glGetUniformLocation(heat_trail_program, "u_heat"), 0);
    pressure_program = link(tonemap_vertex_source, pressure_fragment_source);
    ground_program = link(lit_vertex_source, ground_fragment_source);
    ground_beam_vis_program = link(lit_vertex_source, ground_beam_vis_source);
    stamp_program = link(lit_vertex_source, stamp_fragment_source);
    glUseProgram(stamp_program);
    glUniform1i(glGetUniformLocation(stamp_program, "texture0"), 0);
    u_stamp_target_size = glGetUniformLocation(stamp_program, "target_size");
    u_stamp_kind = glGetUniformLocation(stamp_program, "u_kind");
    u_stamp_pass = glGetUniformLocation(stamp_program, "u_pass");
    u_stamp_wetness = glGetUniformLocation(stamp_program, "u_wetness");
    smoke_solver_program = link(smoke_rect_source, smoke_solver_source);
    smoke_splat_program = link(smoke_rect_source, smoke_splat_source);
    smoke_impulse_program = link(smoke_rect_source, smoke_impulse_source);
    smoke_program = link(smoke_field_source, smoke_fragment_source);
    blit_program = link(tonemap_vertex_source, blit_fragment_source);
    glUseProgram(blit_program);
    glUniform1i(glGetUniformLocation(blit_program, "source"), 0);
    fill_program = link(tonemap_vertex_source, stamp_fragment_source);
    glUseProgram(fill_program);
    glUniform1i(glGetUniformLocation(fill_program, "texture0"), 0);
    u_fill_kind = glGetUniformLocation(fill_program, "u_kind");
    u_fill_pass = glGetUniformLocation(fill_program, "u_pass");
    u_fill_wetness = glGetUniformLocation(fill_program, "u_wetness");
    glGenVertexArrays(1, &beam_array);
    glBindVertexArray(beam_array);
    glGenBuffers(1, &beam_buffer);
    glBindBuffer(GL_ARRAY_BUFFER, beam_buffer);
    glEnableVertexAttribArray(0);
    glVertexAttribPointer(0, 4, GL_FLOAT, GL_FALSE, 16, (void *)0);
  }
  rtx = enabled;
  world = false;
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
void GL_ENTRY(w2c_host_texture_copy)(struct w2c_host *, u32 destination, u32 source) {
  Target &from = target_or_back((int)source);
  if (!from.framebuffer)
    return;
  drop_ground((int)destination);
  Target &to = textures[(int)destination];
  if (to.width != from.width || to.height != from.height || !to.framebuffer) {
    release(to);
    to.width = from.width;
    to.height = from.height;
    to.logical_width = from.logical_width;
    to.logical_height = from.logical_height;
    to.flags = 1;
    allocate(to);
  }
  glBindFramebuffer(GL_READ_FRAMEBUFFER, from.framebuffer);
  glBindFramebuffer(GL_DRAW_FRAMEBUFFER, to.framebuffer);
  glBlitFramebuffer(0, 0, from.width, from.height, 0, 0, from.width, from.height, GL_COLOR_BUFFER_BIT, GL_NEAREST);
  bind_target();
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
// A draw through the device's own shading into the bound target `t`.
static void device_draw(const Target &t, u32 primitive, u32 vertices, u32 vertex_count, u32 indices,
                        u32 primitive_count) {
  glUseProgram(program);
  glUniform2f(u_target_size, (float)t.logical_width, (float)t.logical_height);
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
    glSamplerParameteri(samplers[s], GL_TEXTURE_WRAP_S, address(stage_states[s][TSS_ADDRESSU]));
    glSamplerParameteri(samplers[s], GL_TEXTURE_WRAP_T, address(stage_states[s][TSS_ADDRESSV]));
    glSamplerParameteri(samplers[s], GL_TEXTURE_MAG_FILTER, stage_states[s][TSS_MAGFILTER] >= 2 ? GL_LINEAR : GL_NEAREST);
    glSamplerParameteri(samplers[s], GL_TEXTURE_MIN_FILTER, stage_states[s][TSS_MINFILTER] >= 2 ? GL_LINEAR : GL_NEAREST);
  }
  glActiveTexture(GL_TEXTURE0);
  glUniform2iv(u_has_texture, 1, has);
  glUniform2iv(u_reconstruction, 1, filters);
  glUniform2iv(u_color_op, 1, cop);
  glUniform2iv(u_color_arg1, 1, ca1);
  glUniform2iv(u_color_arg2, 1, ca2);
  glUniform2iv(u_alpha_op, 1, aop);
  glUniform2iv(u_alpha_arg1, 1, aa1);
  glUniform2iv(u_alpha_arg2, 1, aa2);
  unsigned f = render_states[RS_TEXTUREFACTOR];
  glUniform4f(u_factor, (f >> 16 & 255) / 255.0f, (f >> 8 & 255) / 255.0f, (f & 255) / 255.0f, (f >> 24) / 255.0f);
  glUniform1i(u_alpha_test, render_states[RS_ALPHATESTENABLE] != 0);
  glUniform1f(u_alpha_ref, (float)(render_states[RS_ALPHAREF] & 255));
  glUniform1i(u_alpha_func, (GLint)render_states[RS_ALPHAFUNC]);

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
void GL_ENTRY(w2c_host_draw)(struct w2c_host *, u32 primitive, u32 vertices, u32 vertex_count, u32 indices,
                   u32 primitive_count) {
  if (gpu_timers) {
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
  // is blood, the materials if it has one.
  bool marked = rtx && ground_kind != HOST_GROUND_END && current_target && (t.flags & TARGET_RENDER);
  Ground *g = marked ? &ground_of(current_target) : nullptr;
  device_draw(t, primitive, vertices, vertex_count, indices, primitive_count);
  if (!g)
    return;
  if (ground_kind != HOST_GROUND_BLOOD) {
    bind_framebuffer(g->substrate);
    device_draw(g->substrate, primitive, vertices, vertex_count, indices, primitive_count);
  }
  if (ground_kind != HOST_GROUND_DECAL)
    stamp_ground(*g, ground_kind, primitive, vertices, vertex_count, indices, primitive_count);
  bind_target();
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
  if (!rtx)
    return;
  Target &t = drawing_target(current_target);
  glUseProgram(beam_program);
  glUniform2f(u_beam_target_size, (float)t.logical_width, (float)t.logical_height);
  glUniform1f(u_beam_length, length);
  glUniform1f(u_beam_step, step);
  glUniform4f(u_beam_color, (color >> 16 & 255) / 255.0f, (color >> 8 & 255) / 255.0f, (color & 255) / 255.0f,
              (color >> 24) / 255.0f);
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
  glUseProgram(effect_program);
  glUniform2f(u_effect_target_size, (float)t.logical_width,
              (float)t.logical_height);
  glUniform1i(u_effect_kind, kind);
  glUniform4fv(u_effect_params, 3, params);
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
  if (!rtx)
    return;
  const float params[12] = {};
  draw_effect_vertices((const EffectVertex *)(client_memory() + vertices),
                       count, kind, params);
}
void GL_ENTRY(w2c_host_scene)(struct w2c_host *, u32 view, u32 lights, u32 count) {
  const float *v = (const float *)(client_memory() + view);
  scene_camera[0] = v[0], scene_camera[1] = v[1], scene_seconds = v[2];
  ground_size[0] = v[3], ground_size[1] = v[4];
  memcpy(beam_gain, v + 5, sizeof beam_gain);
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
  }
}
void GL_ENTRY(w2c_host_pressure)(struct w2c_host *, u32 fronts, u32 count) {
  const float *f = (const float *)(client_memory() + fronts);
  pressure_fronts.assign(f, f + count * 4);
}
// The frame's footprints into the trail buffer (heat_vision.py's update): fade
// it by the run's clock since the last frame, or start it over after a rewind,
// a long gap or a new terrain, then keep each footprint's warmth where higher.
void GL_ENTRY(w2c_host_heat)(struct w2c_host *, u32 footprints, u32 count) {
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
  glUseProgram(p);
  glUniform2f(glGetUniformLocation(p, "target_size"), (float)width, (float)height);
  glUniform2f(glGetUniformLocation(p, "camera"), 0, 0);
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
    glUniform1f(glGetUniformLocation(p, "u_fade"), 1 - powf(0.5f, gap / HEAT_HALF_LIFE_S));
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
    glUniform1f(glGetUniformLocation(p, "u_fade"), -1);
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
  glUseProgram(p);
  glUniform2f(glGetUniformLocation(p, "target_size"), (float)t.logical_width, (float)t.logical_height);
  glUniform2f(glGetUniformLocation(p, "camera"), scene_camera[0], scene_camera[1]);
  glUniform2fv(glGetUniformLocation(p, "u_ground_size"), 1, ground_size);
  glUniform1f(glGetUniformLocation(p, "u_alpha"), alpha);
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
  ground_kind = (int)kind;
  ground_seconds = seconds;
}
void GL_ENTRY(w2c_host_smoke)(struct w2c_host *, u32 commands, u32 count) {
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
      glUseProgram(p);
      glUniform4fv(glGetUniformLocation(p, "u_source"), 1, c + 5);
      glUniform4fv(glGetUniformLocation(p, "u_motion"), 1, c + 9);
      glUniform1f(glGetUniformLocation(p, "u_rotation"), c[13]);
      glUniform4fv(glGetUniformLocation(p, "u_flow"), 1, c + 14);
      smoke_add(p, c + 1);
      c += 18;
      break;
    }
    case SMOKE_IMPULSE: {
      GLuint p = smoke_impulse_program;
      glUseProgram(p);
      glUniform4fv(glGetUniformLocation(p, "u_segment"), 1, c + 5);
      glUniform4fv(glGetUniformLocation(p, "u_impulse"), 1, c + 9);
      glUniform4fv(glGetUniformLocation(p, "u_phase"), 1, c + 13);
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
    default:
      client_fatal("Unknown smoke command");
    }
  }
  bind_target();
}
void GL_ENTRY(w2c_host_smoke_draw)(struct w2c_host *, u32 view, u32 lights, u32 light_count, u32 sights,
                                   u32 sight_count) {
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
  glUseProgram(p);
  auto at = [p](const char *name) { return glGetUniformLocation(p, name); };
  glUniform4fv(at("rect"), 1, v);
  glUniform2f(at("target_size"), (float)t.logical_width, (float)t.logical_height);
  glUniform1i(at("texture0"), 0);
  glUniform1i(at("u_state_flip"), 1);
  glUniform2fv(at("u_origin"), 1, v + 4);
  glUniform2fv(at("u_size"), 1, v + 6);
  glUniform1f(at("u_opacity"), v[8]);
  glUniform1i(at("u_debug"), 0);
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
  bind_target();
  glUseProgram(blit_program);
  glBlendFunc(GL_ONE, GL_ONE_MINUS_SRC_ALPHA);
  glColorMask(GL_TRUE, GL_TRUE, GL_TRUE, GL_TRUE);
  glBindTexture(GL_TEXTURE_2D, smoke_composite.texture);
  glDrawArrays(GL_TRIANGLE_STRIP, 0, 4);
}
void GL_ENTRY(w2c_host_occlusion)(struct w2c_host *, u32 grid, u32 values, u32 count) {
  const float *g = (const float *)(client_memory() + grid);
  occlusion_grid[0] = g[0], occlusion_grid[1] = g[1], occlusion_grid[2] = count ? g[2] : 0, occlusion_grid[3] = g[3];
  occlusion_cell = g[4];
  dynamic_shadows = g[5] != 0;
  if (!count)
    return;
  // Whole rows, and a texture that grows in powers of two as crowds do.
  int rows = (int)((count + OCCLUSION_WIDTH * 4 - 1) / (OCCLUSION_WIDTH * 4));
  if (rows > occlusion_rows) {
    occlusion_rows = 1;
    while (occlusion_rows < rows)
      occlusion_rows *= 2;
    if (!occlusion_texture)
      glGenTextures(1, &occlusion_texture);
    glBindTexture(GL_TEXTURE_2D, occlusion_texture);
    glTexImage2D(GL_TEXTURE_2D, 0, GL_RGBA32F, OCCLUSION_WIDTH, occlusion_rows, 0, GL_RGBA, GL_FLOAT, nullptr);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_NEAREST);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_NEAREST);
  }
  std::vector<float> texels((size_t)rows * OCCLUSION_WIDTH * 4);
  memcpy(texels.data(), client_memory() + values, (size_t)count * 4);
  glBindTexture(GL_TEXTURE_2D, occlusion_texture);
  glTexSubImage2D(GL_TEXTURE_2D, 0, 0, 0, OCCLUSION_WIDTH, rows, GL_RGBA, GL_FLOAT, texels.data());
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
    return;
  }
  Target &back = textures[0];
  if (!rtx || !back.framebuffer)
    return;
  if (pass == HOST_PASS_WORLD_BEGIN) { // The world goes over what the frame drew so far.
    if (hdr.width != back.width || hdr.height != back.height || !hdr.framebuffer) {
      release(hdr);
      hdr.width = back.width;
      hdr.height = back.height;
      hdr.flags = back.flags | TARGET_HALF_FLOAT;
      allocate(hdr);
    }
    hdr.logical_width = back.logical_width;
    hdr.logical_height = back.logical_height;
    glBindFramebuffer(GL_READ_FRAMEBUFFER, back.framebuffer);
    glBindFramebuffer(GL_DRAW_FRAMEBUFFER, hdr.framebuffer);
    glBlitFramebuffer(0, 0, back.width, back.height, 0, 0, hdr.width, hdr.height, GL_COLOR_BUFFER_BIT, GL_NEAREST);
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
      glUseProgram(pressure_program);
      glUniform1i(glGetUniformLocation(pressure_program, "texture0"), 0);
      glUniform2f(glGetUniformLocation(pressure_program, "u_size"), (float)hdr.width, (float)hdr.height);
      glUniform1i(glGetUniformLocation(pressure_program, "u_count"), count);
      glUniform4fv(glGetUniformLocation(pressure_program, "u_fronts"), count, fronts.data());
      glUniform4fv(glGetUniformLocation(pressure_program, "u_strength"), (count + 3) / 4, strengths.data());
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
    glBindFramebuffer(GL_FRAMEBUFFER, back.framebuffer);
    glViewport(0, 0, back.width, back.height);
    glUseProgram(tonemap_program);
    glUniform1f(u_tonemap_headroom, edr_headroom);
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
