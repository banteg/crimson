// The Direct3D 8 subset the game module's device sends, on OpenGL 3.3 core
// (OpenGL ES 3.0 / WebGL2 in the browser). Render targets and the back buffer
// are framebuffer textures whose row 0 is the image's top row, as uploaded
// textures are; presenting flips the back buffer into the window. In RTX mode
// (game/rtx.cpp, native only) the world draws into a half-float target that a
// tonemap then puts on a half-float back buffer, so highlights can exceed white.
#include "client.h"
#include "client_shaders.h"
#include "device_states.h"
#include <math.h>
#include <stdio.h>
#include <string.h>
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
// Each uploaded artwork's texels in the module (it keeps them), for the creature
// thickness maps made on a creature atlas's first lit draw.
std::unordered_map<int, u32> texel_addresses;
std::unordered_map<int, GLuint> thickness_maps;

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
  if (t.flags & TARGET_HALF_FLOAT)
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

// A creature atlas's part sizes (renderer_thickness), made once it is lit; the
// shader reads them only with lights.
GLuint thickness_map(int id) {
  auto made = thickness_maps.find(id);
  if (made != thickness_maps.end())
    return made->second;
  auto t = textures.find(id);
  auto texels = texel_addresses.find(id);
  if (!light_count || t == textures.end() || texels == texel_addresses.end())
    return blank_texture;
  std::vector<unsigned char> sizes =
      renderer_thickness(client_memory() + texels->second, t->second.logical_width, t->second.logical_height);
  GLuint texture;
  glGenTextures(1, &texture);
  glBindTexture(GL_TEXTURE_2D, texture);
  glPixelStorei(GL_UNPACK_ALIGNMENT, 1);
  glTexImage2D(GL_TEXTURE_2D, 0, GL_R8, t->second.logical_width, t->second.logical_height, 0, GL_RED,
               GL_UNSIGNED_BYTE, sizes.data());
  glPixelStorei(GL_UNPACK_ALIGNMENT, 4);
  glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_LINEAR);
  glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_LINEAR);
  glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_S, GL_CLAMP_TO_EDGE);
  glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_T, GL_CLAMP_TO_EDGE);
  return thickness_maps[id] = texture;
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

// A draw in an RTX creature, player or bonus batch, lit as the Python port
// lights them: creatures (their ambient fill is 0.6) and bonuses always, players
// only under lights.
bool lit_draw(u32 primitive, u32 vertices, u32 vertex_count, u32 indices, u32 primitive_count) {
  if (!rtx || !world || !material || (material == HOST_PASS_PLAYERS && !light_count))
    return false;
  Target &t = drawing_target(current_target);
  LitProgram &p = material == HOST_PASS_PLAYERS ? player_lit : material == MATERIAL_BONUS ? bonus_lit : creature_lit;
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
  glBindTexture(GL_TEXTURE_2D, material == HOST_PASS_CREATURES && present ? thickness_map(bound[0]) : blank_texture);
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
}

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
    create_lit(creature_lit, creature_fragment_source);
    create_lit(player_lit, player_fragment_source);
    create_lit(bonus_lit, bonus_fragment_source);
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
  release(it->second);
  textures.erase(it);
  texel_addresses.erase((int)id);
  auto map = thickness_maps.find((int)id);
  if (map != thickness_maps.end()) {
    glDeleteTextures(1, &map->second);
    thickness_maps.erase(map);
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
  bind_target();
}
void GL_ENTRY(w2c_host_clear)(struct w2c_host *, u32 color) {
  Target &t = drawing_target(current_target);
  glColorMask(GL_TRUE, GL_TRUE, GL_TRUE, GL_TRUE);
  glClearColor((color >> 16 & 255) / 255.0f, (color >> 8 & 255) / 255.0f, (color & 255) / 255.0f,
               t.flags & 2 ? 1.0f : (color >> 24) / 255.0f);
  glClear(GL_COLOR_BUFFER_BIT);
}
void GL_ENTRY(w2c_host_draw)(struct w2c_host *, u32 primitive, u32 vertices, u32 vertex_count, u32 indices,
                   u32 primitive_count) {
  if (lit_draw(primitive, vertices, vertex_count, indices, primitive_count))
    return;
  Target &t = drawing_target(current_target);
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
  glBindVertexArray(beam_array);
  glBindBuffer(GL_ARRAY_BUFFER, beam_buffer);
  glBufferData(GL_ARRAY_BUFFER, 16 * sizeof(float), client_memory() + corners, GL_STREAM_DRAW);
  glDrawArrays(GL_TRIANGLE_FAN, 0, 4);
}
void GL_ENTRY(w2c_host_scene)(struct w2c_host *, u32 camera, u32 lights, u32 count) {
  memcpy(scene_camera, client_memory() + camera, sizeof scene_camera);
  light_count = (int)count < MAX_LIGHTS ? (int)count : MAX_LIGHTS;
  const float *packed = (const float *)(client_memory() + lights);
  for (int i = 0; i < light_count; ++i) {
    memcpy(light_pos + i * 4, packed + i * 16, 16);
    memcpy(light_rgb + i * 4, packed + i * 16 + 4, 16);
    memcpy(light_dir + i * 4, packed + i * 16 + 8, 16);
    memcpy(light_response + i * 4, packed + i * 16 + 12, 16);
  }
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
  material = MATERIAL_BONUS;
  bonus_emblem = (int)emblem;
  bonus_grid[0] = grid_x, bonus_grid[1] = grid_y;
  bonus_center[0] = center_x, bonus_center[1] = center_y;
}
void GL_ENTRY(w2c_host_render_pass)(struct w2c_host *, u32 pass) {
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
    glBindFramebuffer(GL_FRAMEBUFFER, back.framebuffer);
    glViewport(0, 0, back.width, back.height);
    glUseProgram(tonemap_program);
    glUniform1f(u_tonemap_headroom, edr_headroom);
    glDisable(GL_BLEND);
    glDisable(GL_CULL_FACE);
    glColorMask(GL_TRUE, GL_TRUE, GL_TRUE, GL_TRUE);
    glActiveTexture(GL_TEXTURE0);
    glBindTexture(GL_TEXTURE_2D, hdr.texture);
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
