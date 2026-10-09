// The Direct3D 8 subset the game module's device sends, on OpenGL 3.3 core
// (OpenGL ES 3.0 / WebGL2 in the browser). Render targets and the back buffer
// are framebuffer textures whose row 0 is the image's top row, as uploaded
// textures are; presenting flips the back buffer into the window.
#include "client.h"
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

namespace {

// Direct3D 8 values the device forwards.
enum {
  RS_ALPHATESTENABLE = 15,
  RS_SRCBLEND = 19,
  RS_DESTBLEND = 20,
  RS_CULLMODE = 22,
  RS_ALPHAREF = 24,
  RS_ALPHAFUNC = 25,
  RS_ALPHABLENDENABLE = 27,
  RS_TEXTUREFACTOR = 60,
  RS_COLORWRITEENABLE = 168,
  RS_BLENDOP = 171,
  TSS_COLOROP = 1,
  TSS_COLORARG1 = 2,
  TSS_COLORARG2 = 3,
  TSS_ALPHAOP = 4,
  TSS_ALPHAARG1 = 5,
  TSS_ALPHAARG2 = 6,
  TSS_ADDRESSU = 13,
  TSS_ADDRESSV = 14,
  TSS_MAGFILTER = 16,
  TSS_MINFILTER = 17,
  STAGES = 2,
};

struct Target {
  GLuint texture = 0, framebuffer = 0;
  int width = 0, height = 0, flags = 0;
};
std::unordered_map<int, Target> textures; // id 0 is the back buffer
int current_target = 0;
unsigned render_states[256];
unsigned stage_states[STAGES][32];
int bound[STAGES];
GLuint program, present_program, vertex_array, vertex_buffer, index_buffer, samplers[STAGES], gamma_texture;
// Bound to a stage with no texture: the shader never samples it, but a sampler
// needs a complete texture behind it.
GLuint blank_texture;
GLint u_target_size, u_has_texture, u_color_op, u_color_arg1, u_color_arg2, u_alpha_op, u_alpha_arg1, u_alpha_arg2,
    u_factor, u_alpha_test, u_alpha_ref, u_alpha_func;

const char *vertex_source = SHADER_HEADER R"(
layout(location = 0) in vec4 position; // x, y, z, rhw in pixels
layout(location = 1) in vec4 diffuse;  // D3DCOLOR bytes: b, g, r, a
layout(location = 2) in vec2 uv;
uniform vec2 target_size;
out vec4 v_diffuse;
out vec2 v_uv;
void main() {
  // Direct3D 8 puts pixel centers at integer coordinates; OpenGL at half-integers.
  gl_Position = vec4((position.xy + 0.5) / target_size * 2.0 - 1.0, 0.0, 1.0);
  v_diffuse = diffuse.zyxw;
  v_uv = uv;
}
)";

// The fixed-function texture stages, alpha test included.
const char *fragment_source = SHADER_HEADER R"(
in vec4 v_diffuse;
in vec2 v_uv;
out vec4 color;
uniform sampler2D texture0, texture1;
uniform int has_texture[2], color_op[2], color_arg1[2], color_arg2[2], alpha_op[2], alpha_arg1[2], alpha_arg2[2];
uniform vec4 factor;
uniform int alpha_test, alpha_func;
uniform float alpha_ref;
vec4 argument(int a, vec4 current, vec4 texel) {
  int which = a & 7;
  vec4 v = which == 1 ? current : which == 2 ? texel : which == 3 ? factor : v_diffuse;
  if ((a & 0x10) != 0) v = 1.0 - v;
  if ((a & 0x20) != 0) v = vec4(v.a);
  return v;
}
vec4 operation(int op, vec4 a, vec4 b) {
  if (op == 2) return a;
  if (op == 3) return b;
  if (op == 4) return a * b;
  if (op == 5) return a * b * 2.0;
  if (op == 6) return a * b * 4.0;
  if (op == 7) return a + b;
  if (op == 8) return a + b - 0.5;
  if (op == 9) return (a + b - 0.5) * 2.0;
  if (op == 10) return a - b;
  if (op == 11) return a + b - a * b;
  if (op == 24) return vec4(clamp(4.0 * dot(a.rgb - 0.5, b.rgb - 0.5), 0.0, 1.0));
  return a;
}
bool passes(float a) {
  float r = alpha_ref;
  if (alpha_func == 1) return false;
  if (alpha_func == 2) return a < r;
  if (alpha_func == 3) return a == r;
  if (alpha_func == 4) return a <= r;
  if (alpha_func == 5) return a > r;
  if (alpha_func == 6) return a != r;
  if (alpha_func == 7) return a >= r;
  return true;
}
void main() {
  vec4 current = v_diffuse;
  for (int s = 0; s < 2; ++s) {
    if (color_op[s] == 1) break;
    vec4 texel = has_texture[s] != 0 ? (s == 0 ? texture(texture0, v_uv) : texture(texture1, v_uv)) : vec4(1.0);
    vec4 c = clamp(operation(color_op[s], argument(color_arg1[s], current, texel), argument(color_arg2[s], current, texel)), 0.0, 1.0);
    float a = alpha_op[s] == 1 ? current.a
        : clamp(operation(alpha_op[s], argument(alpha_arg1[s], current, texel), argument(alpha_arg2[s], current, texel)).a, 0.0, 1.0);
    current = vec4(c.rgb, a);
  }
  // Direct3D compares the 8-bit alpha with the reference.
  if (alpha_test != 0 && !passes(floor(current.a * 255.0 + 0.5))) discard;
  color = current;
}
)";

const char *present_vertex_source = SHADER_HEADER R"(
out vec2 v_uv;
void main() {
  vec2 corner = vec2(float(gl_VertexID & 1), float(gl_VertexID >> 1));
  gl_Position = vec4(corner * 2.0 - 1.0, 0.0, 1.0);
  v_uv = vec2(corner.x, 1.0 - corner.y); // the back buffer's row 0 is the window's top
}
)";
const char *present_fragment_source = SHADER_HEADER R"(
in vec2 v_uv;
out vec4 color;
uniform sampler2D back_buffer, gamma;
void main() {
  vec3 c = texture(back_buffer, v_uv).rgb;
  // The device's gamma ramp, one 256-entry table per channel.
  color = vec4(texture(gamma, vec2(c.r * 255.0 / 256.0 + 0.5 / 256.0, 0.5)).r,
               texture(gamma, vec2(c.g * 255.0 / 256.0 + 0.5 / 256.0, 0.5)).g,
               texture(gamma, vec2(c.b * 255.0 / 256.0 + 0.5 / 256.0, 0.5)).b, 1.0);
}
)";

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

Target &target_or_back(int id) {
  auto it = textures.find(id);
  return it != textures.end() ? it->second : textures[0];
}

void allocate(Target &t) {
  glGenTextures(1, &t.texture);
  glBindTexture(GL_TEXTURE_2D, t.texture);
  glTexImage2D(GL_TEXTURE_2D, 0, GL_RGBA8, t.width, t.height, 0, GL_RGBA, GL_UNSIGNED_BYTE, nullptr);
  glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_LINEAR);
  glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_LINEAR);
  glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_S, GL_CLAMP_TO_EDGE);
  glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_T, GL_CLAMP_TO_EDGE);
  if (t.flags & 1) {
    glGenFramebuffers(1, &t.framebuffer);
    glBindFramebuffer(GL_FRAMEBUFFER, t.framebuffer);
    glFramebufferTexture2D(GL_FRAMEBUFFER, GL_COLOR_ATTACHMENT0, GL_TEXTURE_2D, t.texture, 0);
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

void bind_target() {
  Target &t = target_or_back(current_target);
  glBindFramebuffer(GL_FRAMEBUFFER, t.framebuffer);
  glViewport(0, 0, t.width, t.height);
}

} // namespace

void renderer_init() {
  program = link(vertex_source, fragment_source);
  present_program = link(present_vertex_source, present_fragment_source);
  u_target_size = glGetUniformLocation(program, "target_size");
  u_has_texture = glGetUniformLocation(program, "has_texture");
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

Viewport renderer_viewport(int window_width, int window_height) {
  Target &back = textures[0];
  float scale = fminf((float)window_width / back.width, (float)window_height / back.height);
  float width = back.width * scale, height = back.height * scale;
  return {(window_width - width) / 2, (window_height - height) / 2, width, height, back.width, back.height};
}

void renderer_present(int window_width, int window_height) {
  Target &back = textures[0];
  if (!back.texture)
    return;
  Viewport v = renderer_viewport(window_width, window_height);
  glBindFramebuffer(GL_FRAMEBUFFER, 0);
  glViewport(0, 0, window_width, window_height);
  glColorMask(GL_TRUE, GL_TRUE, GL_TRUE, GL_TRUE);
  glDisable(GL_BLEND);
  glDisable(GL_CULL_FACE);
  glClearColor(0, 0, 0, 1);
  glClear(GL_COLOR_BUFFER_BIT);
  glViewport((GLint)v.x, (GLint)v.y, (GLsizei)v.width, (GLsizei)v.height);
  glUseProgram(present_program);
  glActiveTexture(GL_TEXTURE1);
  glBindTexture(GL_TEXTURE_2D, gamma_texture);
  glActiveTexture(GL_TEXTURE0);
  glBindTexture(GL_TEXTURE_2D, back.texture);
  glBindSampler(0, 0);
  glBindSampler(1, 0);
  // Whole-number scales stay sharp.
  bool exact = fmodf(v.width, (float)back.width) == 0;
  glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, exact ? GL_NEAREST : GL_LINEAR);
  glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, exact ? GL_NEAREST : GL_LINEAR);
  glDrawArrays(GL_TRIANGLE_STRIP, 0, 4);
  glBindTexture(GL_TEXTURE_2D, 0);
}

void renderer_resume() { bind_target(); }

// The kept frame (host_frame_hold): the back buffer copied aside, and back.
Target held;

// The back buffer as top-down RGBA rows.
std::vector<unsigned char> renderer_capture(int &width, int &height) {
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
void w2c_host_frame_hold(struct w2c_host *, u32 op) {
  Target &back = textures[0];
  if (!back.framebuffer)
    return;
  if (held.width != back.width || held.height != back.height) {
    release(held);
    held.width = back.width;
    held.height = back.height;
    held.flags = 1;
    allocate(held);
  }
  bool save = op == 1; // HOST_FRAME_SAVE (game/host_abi.h); 2 shows it
  glBindFramebuffer(GL_READ_FRAMEBUFFER, save ? back.framebuffer : held.framebuffer);
  glBindFramebuffer(GL_DRAW_FRAMEBUFFER, save ? held.framebuffer : back.framebuffer);
  glBlitFramebuffer(0, 0, back.width, back.height, 0, 0, back.width, back.height, GL_COLOR_BUFFER_BIT, GL_NEAREST);
  bind_target();
}
void w2c_host_texture_copy(struct w2c_host *, u32 destination, u32 source) {
  Target &from = target_or_back((int)source);
  if (!from.framebuffer)
    return;
  Target &to = textures[(int)destination];
  if (to.width != from.width || to.height != from.height || !to.framebuffer) {
    release(to);
    to.width = from.width;
    to.height = from.height;
    to.flags = 1;
    allocate(to);
  }
  glBindFramebuffer(GL_READ_FRAMEBUFFER, from.framebuffer);
  glBindFramebuffer(GL_DRAW_FRAMEBUFFER, to.framebuffer);
  glBlitFramebuffer(0, 0, from.width, from.height, 0, 0, from.width, from.height, GL_COLOR_BUFFER_BIT, GL_NEAREST);
  bind_target();
}
void w2c_host_back_buffer(struct w2c_host *, u32 width, u32 height) {
  Target &back = textures[0];
  release(back);
  back.width = (int)width;
  back.height = (int)height;
  back.flags = 1 | 2; // the back buffer is X8R8G8B8
  allocate(back);
  current_target = 0;
  bind_target();
}
void w2c_host_texture_create(struct w2c_host *, u32 id, u32 width, u32 height, u32 flags) {
  Target &t = textures[(int)id];
  release(t);
  t.width = (int)width;
  t.height = (int)height;
  t.flags = (int)flags;
  allocate(t);
  bind_target();
}
void w2c_host_texture_upload(struct w2c_host *, u32 id, u32 texels) {
  auto it = textures.find((int)id);
  if (it == textures.end())
    return;
  Target &t = it->second;
  // A8R8G8B8 texels are BGRA bytes.
  std::vector<unsigned char> rgba((size_t)t.width * t.height * 4);
  const u8 *bgra = client_memory() + texels;
  for (size_t i = 0; i < rgba.size(); i += 4) {
    rgba[i] = bgra[i + 2];
    rgba[i + 1] = bgra[i + 1];
    rgba[i + 2] = bgra[i];
    rgba[i + 3] = bgra[i + 3];
  }
  glBindTexture(GL_TEXTURE_2D, t.texture);
  glTexSubImage2D(GL_TEXTURE_2D, 0, 0, 0, t.width, t.height, GL_RGBA, GL_UNSIGNED_BYTE, rgba.data());
}
void w2c_host_texture_release(struct w2c_host *, u32 id) {
  auto it = textures.find((int)id);
  if (it == textures.end() || !id)
    return;
  if (current_target == (int)id)
    current_target = 0;
  release(it->second);
  textures.erase(it);
  bind_target();
}
void w2c_host_render_state(struct w2c_host *, u32 state, u32 value) {
  if (state < 256)
    render_states[state] = value;
}
void w2c_host_texture_stage_state(struct w2c_host *, u32 stage, u32 state, u32 value) {
  if (stage < STAGES && state < 32)
    stage_states[stage][state] = value;
}
void w2c_host_set_texture(struct w2c_host *, u32 stage, u32 id) {
  if (stage < STAGES)
    bound[stage] = (int)id;
}
void w2c_host_set_render_target(struct w2c_host *, u32 id) {
  current_target = (int)id;
  bind_target();
}
void w2c_host_clear(struct w2c_host *, u32 color) {
  Target &t = target_or_back(current_target);
  glColorMask(GL_TRUE, GL_TRUE, GL_TRUE, GL_TRUE);
  glClearColor((color >> 16 & 255) / 255.0f, (color >> 8 & 255) / 255.0f, (color & 255) / 255.0f,
               t.flags & 2 ? 1.0f : (color >> 24) / 255.0f);
  glClear(GL_COLOR_BUFFER_BIT);
}
void w2c_host_draw(struct w2c_host *, u32 primitive, u32 vertices, u32 vertex_count, u32 indices,
                   u32 primitive_count) {
  Target &t = target_or_back(current_target);
  glUseProgram(program);
  glUniform2f(u_target_size, (float)t.width, (float)t.height);
  GLint has[STAGES], cop[STAGES], ca1[STAGES], ca2[STAGES], aop[STAGES], aa1[STAGES], aa2[STAGES];
  for (int s = 0; s < STAGES; ++s) {
    auto it = textures.find(bound[s]);
    bool present = bound[s] && it != textures.end() && it->second.texture;
    has[s] = present;
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
  glUniform1iv(u_has_texture, STAGES, has);
  glUniform1iv(u_color_op, STAGES, cop);
  glUniform1iv(u_color_arg1, STAGES, ca1);
  glUniform1iv(u_color_arg2, STAGES, ca2);
  glUniform1iv(u_alpha_op, STAGES, aop);
  glUniform1iv(u_alpha_arg1, STAGES, aa1);
  glUniform1iv(u_alpha_arg2, STAGES, aa2);
  unsigned f = render_states[RS_TEXTUREFACTOR];
  glUniform4f(u_factor, (f >> 16 & 255) / 255.0f, (f >> 8 & 255) / 255.0f, (f & 255) / 255.0f, (f >> 24) / 255.0f);
  glUniform1i(u_alpha_test, render_states[RS_ALPHATESTENABLE] != 0);
  glUniform1f(u_alpha_ref, (float)(render_states[RS_ALPHAREF] & 255));
  glUniform1i(u_alpha_func, (GLint)render_states[RS_ALPHAFUNC]);

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
  unsigned cull = render_states[RS_CULLMODE];
  if (cull == 2 || cull == 3) {
    glEnable(GL_CULL_FACE);
    glFrontFace(GL_CCW);
    glCullFace(cull == 3 ? GL_BACK : GL_FRONT);
  } else {
    glDisable(GL_CULL_FACE);
  }

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
void w2c_host_gamma_ramp(struct w2c_host *, u32 red, u32 green, u32 blue) {
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
