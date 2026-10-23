// The browser's WebGPU renderer: the same Direct3D 8 subset as renderer.cpp, and
// the RTX mode, whose world draws past white and reaches HDR displays through a
// half-float canvas with extended tone mapping. The page gets the device before
// the module starts (shell.html); renderer_select.cpp picks this renderer then.
// The shaders are renderer.cpp's GLSL translated to WGSL (client/shaders.py).
// Targets keep renderer.cpp's orientation: row 0 is the image's top row.
#ifdef __EMSCRIPTEN__
#include "client.h"
#include "device_states.h"
#include "wgsl_shaders.h"
#include <emscripten.h>
#include <math.h>
#include <string.h>
#include <unordered_map>
#include <vector>
#include <webgpu/webgpu.h>

namespace {

struct Target {
  WGPUTexture texture = nullptr;
  WGPUTextureView view = nullptr;
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
// RTX: the world's HDR target while the world draws, as in renderer.cpp.
bool rtx, world;
Target hdr;
float edr_headroom = 1;
// The kept frame (host_frame_hold) and its anchor.
Target held, anchor;

WGPUDevice device;
WGPUQueue queue;
WGPUSurface surface;
WGPUTextureFormat canvas_format;
// What the canvas is configured with: its size, and whether it shows extended range.
int canvas_width, canvas_height;
bool canvas_extended;
WGPUTexture blank, gamma_texture;
WGPUTextureView blank_view, gamma_view;

WGPUStringView text(const char *s) { return WGPUStringView{s, strlen(s)}; }
WGPUTextureFormat format_of(const Target &t) {
  return t.flags & TARGET_HALF_FLOAT ? WGPUTextureFormat_RGBA16Float : WGPUTextureFormat_RGBA8Unorm;
}

// --- Per-frame streams: vertices, indices and uniforms written once each --------
// A region is written once before the commands that read it are submitted; a full
// stream submits what it holds and starts over.
struct Stream {
  WGPUBuffer buffer = nullptr;
  uint64_t size = 0, used = 0;
  unsigned alignment = 4;
};
Stream vertex_stream{nullptr, 8 << 20}, index_stream{nullptr, 2 << 20}, uniform_stream{nullptr, 4 << 20, 0, 256};

WGPUCommandEncoder encoder;
WGPURenderPassEncoder pass;
WGPUTexture pass_texture;

void end_pass() {
  if (!pass)
    return;
  wgpuRenderPassEncoderEnd(pass);
  wgpuRenderPassEncoderRelease(pass);
  pass = nullptr;
  pass_texture = nullptr;
}

WGPUCommandEncoder commands() {
  if (!encoder)
    encoder = wgpuDeviceCreateCommandEncoder(device, nullptr);
  return encoder;
}

void submit() {
  end_pass();
  if (encoder) {
    WGPUCommandBuffer buffer = wgpuCommandEncoderFinish(encoder, nullptr);
    wgpuQueueSubmit(queue, 1, &buffer);
    wgpuCommandBufferRelease(buffer);
    wgpuCommandEncoderRelease(encoder);
    encoder = nullptr;
  }
  vertex_stream.used = index_stream.used = uniform_stream.used = 0;
}

// Space for `size` bytes in a stream, or none: then the caller submits and asks again.
bool fits(Stream &s, uint64_t size) {
  uint64_t at = (s.used + s.alignment - 1) / s.alignment * s.alignment;
  return at + size <= s.size;
}
uint64_t put(Stream &s, const void *data, uint64_t size) {
  uint64_t at = (s.used + s.alignment - 1) / s.alignment * s.alignment;
  uint64_t padded = (size + 3) & ~3ull;
  if (padded == size) {
    wgpuQueueWriteBuffer(queue, s.buffer, at, data, size);
  } else {
    std::vector<unsigned char> copy(padded);
    memcpy(copy.data(), data, size);
    wgpuQueueWriteBuffer(queue, s.buffer, at, copy.data(), padded);
  }
  s.used = at + padded;
  return at;
}

void begin_pass(Target &t, const WGPUColor *clear) {
  end_pass();
  WGPURenderPassColorAttachment color = WGPU_RENDER_PASS_COLOR_ATTACHMENT_INIT;
  color.view = t.view;
  color.loadOp = clear ? WGPULoadOp_Clear : WGPULoadOp_Load;
  color.storeOp = WGPUStoreOp_Store;
  if (clear)
    color.clearValue = *clear;
  WGPURenderPassDescriptor descriptor = WGPU_RENDER_PASS_DESCRIPTOR_INIT;
  descriptor.colorAttachmentCount = 1;
  descriptor.colorAttachments = &color;
  pass = wgpuCommandEncoderBeginRenderPass(commands(), &descriptor);
  pass_texture = t.texture;
}

void pass_into(Target &t) {
  if (!pass || pass_texture != t.texture)
    begin_pass(t, nullptr);
}

// --- Programs: a WGSL stage pair, its bind group layouts and pipelines ------------
enum VertexInput { NO_VERTICES, DEVICE_VERTICES, BEAM_CORNERS };

struct Program {
  const WgslStage *vert, *frag;
  VertexInput input;
  WGPUShaderModule vert_module, frag_module;
  WGPUBindGroupLayout layouts[2];
  WGPUPipelineLayout layout;
  WGPUBindGroup vertex_group; // group 1: the vertex stage's uniform block alone
  std::unordered_map<uint64_t, WGPURenderPipeline> pipelines;
  std::unordered_map<uint64_t, WGPUBindGroup> groups; // group 0, by its textures and samplers
};
Program classic{&WGSL_CLASSIC_VERT, &WGSL_CLASSIC_FRAG, DEVICE_VERTICES};
Program present_program{&WGSL_PRESENT_VERT, &WGSL_PRESENT_FRAG, NO_VERTICES};
Program blit{&WGSL_FULLSCREEN_VERT, &WGSL_BLIT_FRAG, NO_VERTICES};
Program tonemap{&WGSL_FULLSCREEN_VERT, &WGSL_HDR_TONEMAP_FRAG, NO_VERTICES};
Program beam{&WGSL_BEAM_VERT, &WGSL_BEAM_FRAG, BEAM_CORNERS};
Program creature_lit{&WGSL_CREATURE_VERT, &WGSL_CREATURE_FRAG, DEVICE_VERTICES};
Program player_lit{&WGSL_CREATURE_VERT, &WGSL_PLAYER_FRAG, DEVICE_VERTICES};
Program bonus_lit{&WGSL_CREATURE_VERT, &WGSL_BONUS_FRAG, DEVICE_VERTICES};

// RTX lighting, as in renderer.cpp: the world's lights and camera, the batch
// being drawn, a bonus draw's own material, and each artwork's texels in the
// module for creature thickness.
enum { MAX_LIGHTS = 32 };
int material;
float scene_camera[2];
float light_pos[MAX_LIGHTS * 4], light_rgb[MAX_LIGHTS * 4], light_dir[MAX_LIGHTS * 4], light_response[MAX_LIGHTS * 4];
int light_count;
int bonus_emblem;
float bonus_grid[2], bonus_center[2];
std::unordered_map<int, u32> texel_addresses;
struct Thickness {
  WGPUTexture texture;
  WGPUTextureView view;
};
std::unordered_map<int, Thickness> thickness_maps;
// The creature body grid (host_occlusion), as in renderer.cpp.
enum { OCCLUSION_WIDTH = 256 };
float occlusion_grid[4], occlusion_cell = 64;
int dynamic_shadows, occlusion_rows;
WGPUTexture occlusion_texture;
WGPUTextureView occlusion_view;

WGPUShaderModule module_of(const WgslStage &stage) {
  WGPUShaderSourceWGSL wgsl = WGPU_SHADER_SOURCE_WGSL_INIT;
  wgsl.code = text(stage.source);
  WGPUShaderModuleDescriptor descriptor = WGPU_SHADER_MODULE_DESCRIPTOR_INIT;
  descriptor.nextInChain = &wgsl.chain;
  return wgpuDeviceCreateShaderModule(device, &descriptor);
}

WGPUBindGroupLayout layout_of(const WgslStage &stage, WGPUShaderStage visibility) {
  std::vector<WGPUBindGroupLayoutEntry> entries;
  for (unsigned i = 0; i < stage.binding_count; ++i) {
    const WgslBinding &b = stage.bindings[i];
    if (!*b.name)
      continue;
    WGPUBindGroupLayoutEntry entry = WGPU_BIND_GROUP_LAYOUT_ENTRY_INIT;
    entry.binding = b.binding;
    entry.visibility = visibility;
    if (b.kind == WGSL_UNIFORM) {
      entry.buffer.type = WGPUBufferBindingType_Uniform;
      entry.buffer.hasDynamicOffset = true;
      entry.buffer.minBindingSize = stage.uniform_size;
    } else if (b.kind == WGSL_TEXTURE || b.kind == WGSL_TEXTURE_LOADED) {
      // A texture only loaded may hold 32-bit floats, which WebGPU cannot filter.
      entry.texture.sampleType = b.kind == WGSL_TEXTURE ? WGPUTextureSampleType_Float : WGPUTextureSampleType_UnfilterableFloat;
      entry.texture.viewDimension = WGPUTextureViewDimension_2D;
    } else {
      entry.sampler.type = WGPUSamplerBindingType_Filtering;
    }
    entries.push_back(entry);
  }
  WGPUBindGroupLayoutDescriptor descriptor = WGPU_BIND_GROUP_LAYOUT_DESCRIPTOR_INIT;
  descriptor.entryCount = entries.size();
  descriptor.entries = entries.data();
  return wgpuDeviceCreateBindGroupLayout(device, &descriptor);
}

void create(Program &p) {
  p.vert_module = module_of(*p.vert);
  p.frag_module = module_of(*p.frag);
  p.layouts[0] = layout_of(*p.frag, WGPUShaderStage_Fragment);
  p.layouts[1] = layout_of(*p.vert, WGPUShaderStage_Vertex);
  WGPUPipelineLayoutDescriptor descriptor = WGPU_PIPELINE_LAYOUT_DESCRIPTOR_INIT;
  descriptor.bindGroupLayoutCount = p.vert->uniform_size ? 2 : 1;
  descriptor.bindGroupLayouts = p.layouts;
  p.layout = wgpuDeviceCreatePipelineLayout(device, &descriptor);
  if (p.vert->uniform_size) {
    WGPUBindGroupEntry entry = WGPU_BIND_GROUP_ENTRY_INIT;
    entry.binding = 0;
    entry.buffer = uniform_stream.buffer;
    entry.size = p.vert->uniform_size;
    WGPUBindGroupDescriptor group = WGPU_BIND_GROUP_DESCRIPTOR_INIT;
    group.layout = p.layouts[1];
    group.entryCount = 1;
    group.entries = &entry;
    p.vertex_group = wgpuDeviceCreateBindGroup(device, &group);
  }
}

// A stage's uniform block, filled by member name as glUniform* would.
struct Uniforms {
  const WgslStage &stage;
  unsigned char data[4096] = {};
  explicit Uniforms(const WgslStage &s) : stage(s) {}
  Uniforms &set(const char *name, const void *value, size_t size) {
    for (unsigned i = 0; i < stage.uniform_count; ++i)
      if (!strcmp(stage.uniforms[i].name, name))
        memcpy(data + stage.uniforms[i].offset, value, size);
    return *this;
  }
  Uniforms &f(const char *name, float x) { return set(name, &x, 4); }
  Uniforms &v2(const char *name, float x, float y) {
    float v[2] = {x, y};
    return set(name, v, 8);
  }
  Uniforms &v4(const char *name, float x, float y, float z, float w) {
    float v[4] = {x, y, z, w};
    return set(name, v, 16);
  }
  Uniforms &i(const char *name, int x) { return set(name, &x, 4); }
  Uniforms &i2(const char *name, const int *v) { return set(name, v, 8); }
};

// The pipeline state a draw takes from the device's render states.
struct Output {
  WGPUTextureFormat format;
  bool blend = false;
  WGPUBlendFactor src = WGPUBlendFactor_One, dst = WGPUBlendFactor_Zero;
  WGPUBlendOperation op = WGPUBlendOperation_Add;
  unsigned mask = 0xf;
  WGPUPrimitiveTopology topology = WGPUPrimitiveTopology_TriangleStrip;
  uint64_t key() const {
    return (uint64_t)format | (uint64_t)blend << 8 | (uint64_t)src << 9 | (uint64_t)dst << 17 | (uint64_t)op << 25 |
           (uint64_t)mask << 33 | (uint64_t)topology << 37;
  }
};

WGPUBlendFactor blend_factor(unsigned d3d) {
  switch (d3d) {
  case 1: return WGPUBlendFactor_Zero;
  case 2: return WGPUBlendFactor_One;
  case 3: return WGPUBlendFactor_Src;
  case 4: return WGPUBlendFactor_OneMinusSrc;
  case 5: return WGPUBlendFactor_SrcAlpha;
  case 6: return WGPUBlendFactor_OneMinusSrcAlpha;
  case 7: return WGPUBlendFactor_DstAlpha;
  case 8: return WGPUBlendFactor_OneMinusDstAlpha;
  case 9: return WGPUBlendFactor_Dst;
  case 10: return WGPUBlendFactor_OneMinusDst;
  case 11: return WGPUBlendFactor_SrcAlphaSaturated;
  default: return WGPUBlendFactor_One;
  }
}
WGPUBlendOperation blend_operation(unsigned d3d) {
  switch (d3d) {
  case 2: return WGPUBlendOperation_Subtract;
  case 3: return WGPUBlendOperation_ReverseSubtract;
  case 4: return WGPUBlendOperation_Min;
  case 5: return WGPUBlendOperation_Max;
  default: return WGPUBlendOperation_Add;
  }
}

// The device's blending and color writes onto `t`, as renderer.cpp's apply_output_state.
Output device_output(const Target &t, WGPUPrimitiveTopology topology) {
  Output o;
  o.format = format_of(t);
  o.topology = topology;
  if (render_states[RS_ALPHABLENDENABLE]) {
    o.blend = true;
    o.op = blend_operation(render_states[RS_BLENDOP]);
    // Minimum and maximum ignore the factors, which WebGPU then wants as one.
    bool extreme = o.op == WGPUBlendOperation_Min || o.op == WGPUBlendOperation_Max;
    o.src = extreme ? WGPUBlendFactor_One : blend_factor(render_states[RS_SRCBLEND]);
    o.dst = extreme ? WGPUBlendFactor_One : blend_factor(render_states[RS_DESTBLEND]);
  }
  // An X8R8G8B8 surface keeps its alpha at one.
  o.mask = render_states[RS_COLORWRITEENABLE] & (t.flags & TARGET_OPAQUE ? 7 : 15);
  return o;
}

WGPURenderPipeline pipeline(Program &p, const Output &o) {
  uint64_t key = o.key();
  auto it = p.pipelines.find(key);
  if (it != p.pipelines.end())
    return it->second;
  WGPUVertexAttribute attributes[3] = {WGPU_VERTEX_ATTRIBUTE_INIT, WGPU_VERTEX_ATTRIBUTE_INIT, WGPU_VERTEX_ATTRIBUTE_INIT};
  WGPUVertexBufferLayout buffer = WGPU_VERTEX_BUFFER_LAYOUT_INIT;
  buffer.stepMode = WGPUVertexStepMode_Vertex;
  buffer.attributes = attributes;
  if (p.input == DEVICE_VERTICES) {
    // x, y, z, rhw, D3DCOLOR, u, v: 28 bytes, as host_draw sends them.
    attributes[0].format = WGPUVertexFormat_Float32x4;
    attributes[0].offset = 0;
    attributes[0].shaderLocation = 0;
    attributes[1].format = WGPUVertexFormat_Unorm8x4;
    attributes[1].offset = 16;
    attributes[1].shaderLocation = 1;
    attributes[2].format = WGPUVertexFormat_Float32x2;
    attributes[2].offset = 20;
    attributes[2].shaderLocation = 2;
    buffer.arrayStride = 28;
    buffer.attributeCount = 3;
  } else if (p.input == BEAM_CORNERS) {
    attributes[0].format = WGPUVertexFormat_Float32x4;
    attributes[0].shaderLocation = 0;
    buffer.arrayStride = 16;
    buffer.attributeCount = 1;
  }
  WGPUBlendState blend = WGPU_BLEND_STATE_INIT;
  blend.color.operation = blend.alpha.operation = o.op;
  blend.color.srcFactor = blend.alpha.srcFactor = o.src;
  blend.color.dstFactor = blend.alpha.dstFactor = o.dst;
  WGPUColorTargetState target = WGPU_COLOR_TARGET_STATE_INIT;
  target.format = o.format;
  target.blend = o.blend ? &blend : nullptr;
  target.writeMask = (WGPUColorWriteMask)o.mask;
  WGPUFragmentState fragment = WGPU_FRAGMENT_STATE_INIT;
  fragment.module = p.frag_module;
  fragment.entryPoint = text("main");
  fragment.targetCount = 1;
  fragment.targets = &target;
  WGPURenderPipelineDescriptor descriptor = WGPU_RENDER_PIPELINE_DESCRIPTOR_INIT;
  descriptor.layout = p.layout;
  descriptor.vertex.module = p.vert_module;
  descriptor.vertex.entryPoint = text("main");
  descriptor.vertex.bufferCount = p.input == NO_VERTICES ? 0 : 1;
  descriptor.vertex.buffers = &buffer;
  descriptor.primitive.topology = o.topology;
  // The device never culls (Grim sets D3DCULL_NONE).
  descriptor.primitive.cullMode = WGPUCullMode_None;
  if (o.topology == WGPUPrimitiveTopology_TriangleStrip || o.topology == WGPUPrimitiveTopology_LineStrip)
    descriptor.primitive.stripIndexFormat = WGPUIndexFormat_Uint16;
  descriptor.fragment = &fragment;
  return p.pipelines[key] = wgpuDeviceCreateRenderPipeline(device, &descriptor);
}

// Samplers by their addressing and filters.
std::unordered_map<unsigned, WGPUSampler> samplers;
WGPUAddressMode address(unsigned d3d) {
  return d3d == 2 ? WGPUAddressMode_MirrorRepeat : d3d == 3 || d3d == 4 ? WGPUAddressMode_ClampToEdge : WGPUAddressMode_Repeat;
}
WGPUSampler sampler(unsigned address_u, unsigned address_v, bool linear_mag, bool linear_min) {
  unsigned key = address_u | address_v << 8 | linear_mag << 16 | linear_min << 17;
  auto it = samplers.find(key);
  if (it != samplers.end())
    return it->second;
  WGPUSamplerDescriptor descriptor = WGPU_SAMPLER_DESCRIPTOR_INIT;
  descriptor.addressModeU = address(address_u);
  descriptor.addressModeV = address(address_v);
  descriptor.magFilter = linear_mag ? WGPUFilterMode_Linear : WGPUFilterMode_Nearest;
  descriptor.minFilter = linear_min ? WGPUFilterMode_Linear : WGPUFilterMode_Nearest;
  return samplers[key] = wgpuDeviceCreateSampler(device, &descriptor);
}
WGPUSampler linear_clamp() { return sampler(3, 3, true, true); }
WGPUSampler nearest_clamp() { return sampler(3, 3, false, false); }

// Group 0: a program's fragment uniforms, then each texture and its sampler, by name.
struct Input {
  const char *name;
  WGPUTextureView view;
  WGPUSampler sampler;
};
WGPUBindGroup fragment_group(Program &p, std::initializer_list<Input> inputs) {
  uint64_t key = 0;
  for (const Input &in : inputs)
    key = key * 1000003 ^ (uintptr_t)in.view ^ (uint64_t)(uintptr_t)in.sampler << 32;
  auto it = p.groups.find(key);
  if (it != p.groups.end())
    return it->second;
  std::vector<WGPUBindGroupEntry> entries;
  const WgslStage &stage = *p.frag;
  for (unsigned i = 0; i < stage.binding_count; ++i) {
    const WgslBinding &b = stage.bindings[i];
    if (!*b.name)
      continue;
    WGPUBindGroupEntry entry = WGPU_BIND_GROUP_ENTRY_INIT;
    entry.binding = b.binding;
    if (b.kind == WGSL_UNIFORM) {
      entry.buffer = uniform_stream.buffer;
      entry.size = stage.uniform_size;
    } else {
      const Input *input = nullptr;
      for (const Input &in : inputs)
        if (!strcmp(in.name, b.name))
          input = &in;
      if (b.kind != WGSL_SAMPLER)
        entry.textureView = input ? input->view : blank_view;
      else
        entry.sampler = input ? input->sampler : linear_clamp();
    }
    entries.push_back(entry);
  }
  WGPUBindGroupDescriptor descriptor = WGPU_BIND_GROUP_DESCRIPTOR_INIT;
  descriptor.layout = p.layouts[0];
  descriptor.entryCount = entries.size();
  descriptor.entries = entries.data();
  return p.groups[key] = wgpuDeviceCreateBindGroup(device, &descriptor);
}

// Bind a program's groups with its uniform blocks, written to the stream.
void bind(Program &p, WGPUBindGroup group, const Uniforms *vertex, const Uniforms *fragment) {
  uint32_t offset = fragment ? (uint32_t)put(uniform_stream, fragment->data, p.frag->uniform_size) : 0;
  wgpuRenderPassEncoderSetBindGroup(pass, 0, group, fragment ? 1 : 0, &offset);
  if (vertex) {
    uint32_t vertex_offset = (uint32_t)put(uniform_stream, vertex->data, p.vert->uniform_size);
    wgpuRenderPassEncoderSetBindGroup(pass, 1, p.vertex_group, 1, &vertex_offset);
  }
}

// Everything bound to a texture view goes when the texture does.
void forget_groups() {
  for (Program *p : {&classic, &present_program, &blit, &tonemap, &beam, &creature_lit, &player_lit, &bonus_lit}) {
    for (auto &[key, group] : p->groups)
      wgpuBindGroupRelease(group);
    p->groups.clear();
  }
}

// --- Targets ----------------------------------------------------------------------

void allocate(Target &t) {
  WGPUTextureDescriptor descriptor = WGPU_TEXTURE_DESCRIPTOR_INIT;
  descriptor.size = {(uint32_t)t.width, (uint32_t)t.height, 1};
  descriptor.format = format_of(t);
  descriptor.usage = WGPUTextureUsage_TextureBinding | WGPUTextureUsage_CopyDst | WGPUTextureUsage_CopySrc |
                     WGPUTextureUsage_RenderAttachment;
  t.texture = wgpuDeviceCreateTexture(device, &descriptor);
  t.view = wgpuTextureCreateView(t.texture, nullptr);
  if (t.flags & TARGET_RENDER) {
    // Direct3D's surfaces start black and opaque.
    WGPUColor black = {0, 0, 0, 1};
    begin_pass(t, &black);
    end_pass();
  }
}

void release(Target &t) {
  if (t.texture) {
    if (pass_texture == t.texture)
      end_pass();
    // Commands already recorded may still read it: they hold their own reference,
    // so the texture goes once they ran.
    wgpuTextureViewRelease(t.view);
    wgpuTextureRelease(t.texture);
    forget_groups();
  }
  t = Target{};
}

Target &target_or_back(int id) {
  auto it = textures.find(id);
  return it != textures.end() ? it->second : textures[0];
}

// While the RTX world draws, the back buffer's draws go to the HDR target.
Target &drawing_target(int id) {
  Target &t = target_or_back(id);
  return world && &t == &textures[0] ? hdr : t;
}

// One target's image onto another: a copy when they match, else drawn scaled.
void copy(Target &from, Target &to) {
  end_pass();
  if (from.width == to.width && from.height == to.height && format_of(from) == format_of(to)) {
    WGPUTexelCopyTextureInfo source = WGPU_TEXEL_COPY_TEXTURE_INFO_INIT, destination = WGPU_TEXEL_COPY_TEXTURE_INFO_INIT;
    source.texture = from.texture;
    destination.texture = to.texture;
    WGPUExtent3D extent = {(uint32_t)from.width, (uint32_t)from.height, 1};
    wgpuCommandEncoderCopyTextureToTexture(commands(), &source, &destination, &extent);
    return;
  }
  begin_pass(to, nullptr);
  Output o;
  o.format = format_of(to);
  o.mask = to.flags & TARGET_OPAQUE ? 7 : 15;
  wgpuRenderPassEncoderSetPipeline(pass, pipeline(blit, o));
  bind(blit, fragment_group(blit, {{"source", from.view, linear_clamp()}}), nullptr, nullptr);
  wgpuRenderPassEncoderDraw(pass, 4, 1, 0, 0);
  end_pass();
}

// Reallocate a target in place, keeping its image (scaled once if its size changed).
void reallocate(Target &t, int width, int height, int flags) {
  Target previous = t;
  t.texture = nullptr;
  t.view = nullptr;
  t.width = width;
  t.height = height;
  t.flags = flags;
  allocate(t);
  copy(previous, t);
  release(previous);
}

// The canvas, sized to the window, half-float with extended tone mapping while the
// RTX world can show highlights on an HDR display.
bool hdr_display() { return EM_ASM_INT({ return matchMedia("(dynamic-range: high)").matches ? 1 : 0; }); }
void configure_canvas(int width, int height) {
  bool extended = rtx && hdr_display();
  if (width == canvas_width && height == canvas_height && extended == canvas_extended)
    return;
  canvas_width = width;
  canvas_height = height;
  canvas_extended = extended;
  WGPUSurfaceColorManagement color = WGPU_SURFACE_COLOR_MANAGEMENT_INIT;
  color.colorSpace = WGPUPredefinedColorSpace_SRGB;
  color.toneMappingMode = extended ? WGPUToneMappingMode_Extended : WGPUToneMappingMode_Standard;
  WGPUSurfaceConfiguration config = WGPU_SURFACE_CONFIGURATION_INIT;
  config.nextInChain = &color.chain;
  config.device = device;
  config.format = extended ? WGPUTextureFormat_RGBA16Float : canvas_format;
  config.usage = WGPUTextureUsage_RenderAttachment;
  config.alphaMode = WGPUCompositeAlphaMode_Opaque;
  config.width = width;
  config.height = height;
  wgpuSurfaceConfigure(surface, &config);
  // Browsers report no headroom: twice SDR white is a highlight most HDR displays show without clipping.
  edr_headroom = extended ? 2 : 1;
}

WGPUBuffer stream_buffer(Stream &s, WGPUBufferUsage usage) {
  WGPUBufferDescriptor descriptor = WGPU_BUFFER_DESCRIPTOR_INIT;
  descriptor.size = s.size;
  descriptor.usage = usage | WGPUBufferUsage_CopyDst;
  return s.buffer = wgpuDeviceCreateBuffer(device, &descriptor);
}

WGPUTexture small_texture(int width, const unsigned char *rgba, WGPUTextureView &view) {
  WGPUTextureDescriptor descriptor = WGPU_TEXTURE_DESCRIPTOR_INIT;
  descriptor.size = {(uint32_t)width, 1, 1};
  descriptor.format = WGPUTextureFormat_RGBA8Unorm;
  descriptor.usage = WGPUTextureUsage_TextureBinding | WGPUTextureUsage_CopyDst;
  WGPUTexture texture = wgpuDeviceCreateTexture(device, &descriptor);
  view = wgpuTextureCreateView(texture, nullptr);
  WGPUTexelCopyTextureInfo destination = WGPU_TEXEL_COPY_TEXTURE_INFO_INIT;
  destination.texture = texture;
  WGPUTexelCopyBufferLayout layout = {0, (uint32_t)width * 4, 1};
  WGPUExtent3D extent = {(uint32_t)width, 1, 1};
  wgpuQueueWriteTexture(queue, &destination, rgba, (size_t)width * 4, &layout, &extent);
  return texture;
}

// A creature atlas's part sizes (renderer_thickness), made once it is lit.
WGPUTextureView thickness_map(int id) {
  auto made = thickness_maps.find(id);
  if (made != thickness_maps.end())
    return made->second.view;
  auto t = textures.find(id);
  auto texels = texel_addresses.find(id);
  if (!light_count || t == textures.end() || texels == texel_addresses.end())
    return blank_view;
  int width = t->second.logical_width, height = t->second.logical_height;
  std::vector<unsigned char> sizes = renderer_thickness(client_memory() + texels->second, width, height);
  WGPUTextureDescriptor descriptor = WGPU_TEXTURE_DESCRIPTOR_INIT;
  descriptor.size = {(uint32_t)width, (uint32_t)height, 1};
  descriptor.format = WGPUTextureFormat_R8Unorm;
  descriptor.usage = WGPUTextureUsage_TextureBinding | WGPUTextureUsage_CopyDst;
  Thickness map;
  map.texture = wgpuDeviceCreateTexture(device, &descriptor);
  map.view = wgpuTextureCreateView(map.texture, nullptr);
  WGPUTexelCopyTextureInfo destination = WGPU_TEXEL_COPY_TEXTURE_INFO_INIT;
  destination.texture = map.texture;
  WGPUTexelCopyBufferLayout layout = {0, (uint32_t)width, (uint32_t)height};
  WGPUExtent3D extent = {(uint32_t)width, (uint32_t)height, 1};
  wgpuQueueWriteTexture(queue, &destination, sizes.data(), sizes.size(), &layout, &extent);
  return (thickness_maps[id] = map).view;
}

} // namespace

// --- The renderer's entry points (renderer_select.cpp) ---------------------------------

void wgpu_renderer_init() {
  device = emscripten_webgpu_get_device();
  queue = wgpuDeviceGetQueue(device);
  WGPUEmscriptenSurfaceSourceCanvasHTMLSelector canvas = WGPU_EMSCRIPTEN_SURFACE_SOURCE_CANVAS_HTML_SELECTOR_INIT;
  canvas.selector = text("#canvas");
  WGPUSurfaceDescriptor descriptor = WGPU_SURFACE_DESCRIPTOR_INIT;
  descriptor.nextInChain = &canvas.chain;
  surface = wgpuInstanceCreateSurface(wgpuCreateInstance(nullptr), &descriptor);
  canvas_format = EM_ASM_INT({ return navigator.gpu.getPreferredCanvasFormat() == "rgba8unorm" ? 1 : 0; })
                      ? WGPUTextureFormat_RGBA8Unorm
                      : WGPUTextureFormat_BGRA8Unorm;
  stream_buffer(vertex_stream, WGPUBufferUsage_Vertex);
  stream_buffer(index_stream, WGPUBufferUsage_Index);
  stream_buffer(uniform_stream, WGPUBufferUsage_Uniform);
  for (Program *p : {&classic, &present_program, &blit, &tonemap, &beam, &creature_lit, &player_lit, &bonus_lit})
    create(*p);
  const unsigned char white[4] = {255, 255, 255, 255};
  blank = small_texture(1, white, blank_view);
  // An identity ramp until the device sets one.
  unsigned char identity[256 * 4];
  for (int i = 0; i < 256; ++i)
    identity[i * 4] = identity[i * 4 + 1] = identity[i * 4 + 2] = (unsigned char)i, identity[i * 4 + 3] = 255;
  gamma_texture = small_texture(256, identity, gamma_view);
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

Viewport wgpu_renderer_viewport(int window_width, int window_height) {
  Target &back = textures[0];
  if (window_width <= 0 || window_height <= 0 || back.logical_width <= 0 || back.logical_height <= 0)
    return {};
  double scale = fmin((double)window_width / back.logical_width, (double)window_height / back.logical_height);
  int width = (int)fmax(1, round(back.logical_width * scale));
  int height = (int)fmax(1, round(back.logical_height * scale));
  return {(window_width - width) / 2, (window_height - height) / 2, width, height, back.logical_width, back.logical_height};
}

void wgpu_renderer_resize(int window_width, int window_height) {
  drawable_width = window_width;
  drawable_height = window_height;
  Viewport v = wgpu_renderer_viewport(window_width, window_height);
  Target &back = textures[0];
  // A minimized window can have no drawable pixels. Keep its last image.
  if (!v.width || !back.texture || (back.width == v.width && back.height == v.height))
    return;
  reallocate(back, v.width, v.height, back.flags);
}

void wgpu_renderer_present(int window_width, int window_height) {
  Target &back = textures[0];
  Viewport v = wgpu_renderer_viewport(window_width, window_height);
  if (!back.texture || !v.width)
    return;
  configure_canvas(window_width, window_height);
  end_pass();
  WGPUSurfaceTexture frame = WGPU_SURFACE_TEXTURE_INIT;
  wgpuSurfaceGetCurrentTexture(surface, &frame);
  Target window;
  window.texture = frame.texture;
  window.view = wgpuTextureCreateView(frame.texture, nullptr);
  WGPUColor black = {0, 0, 0, 1};
  begin_pass(window, &black);
  // The canvas's row 0 is its top, as the viewport's origin.
  wgpuRenderPassEncoderSetViewport(pass, (float)v.x, (float)v.y, (float)v.width, (float)v.height, 0, 1);
  Output o;
  o.format = canvas_extended ? WGPUTextureFormat_RGBA16Float : canvas_format;
  wgpuRenderPassEncoderSetPipeline(pass, pipeline(present_program, o));
  // Normally a one-to-one copy; a resize between draw and present may scale once.
  bool exact = v.width == back.width && v.height == back.height;
  bind(present_program,
       fragment_group(present_program, {{"back_buffer", back.view, exact ? nearest_clamp() : linear_clamp()},
                                        {"gamma", gamma_view, nearest_clamp()}}),
       nullptr, nullptr);
  wgpuRenderPassEncoderDraw(pass, 4, 1, 0, 0);
  submit();
  wgpuTextureViewRelease(window.view);
  wgpuTextureRelease(frame.texture);
}

void wgpu_renderer_resume() {}

// Captures are the native client's (CRIMSON_CAPTURE).
std::vector<unsigned char> wgpu_renderer_capture(int &width, int &height) {
  width = height = 0;
  return {};
}

bool wgpu_renderer_set_rtx(bool enabled) {
  rtx = enabled;
  world = false;
  release(hdr);
  // Classic keeps an 8-bit back buffer: its draws saturate at white one by one.
  Target &back = textures[0];
  int flags = enabled ? back.flags | TARGET_HALF_FLOAT : back.flags & ~TARGET_HALF_FLOAT;
  if (back.texture && flags != back.flags)
    reallocate(back, back.width, back.height, flags);
  else
    back.flags = flags;
  return enabled;
}

// The canvas sets the headroom it shows (configure_canvas).
void wgpu_renderer_set_headroom(float) {}

extern "C" {
void wgpu_w2c_host_frame_hold(struct w2c_host *, u32 op) {
  if (op == 5) { // HOST_FRAME_ANCHOR_DROP
    release(anchor);
    return;
  }
  Target &back = textures[0];
  if (!back.texture)
    return;
  Target &from = op == 1 ? back : op == 4 ? anchor : held;
  Target &to = op == 1 || op == 4 ? held : op == 3 ? anchor : back;
  if (!from.texture)
    return;
  // Saved images retain their capture density. Restoring must never shrink the
  // current back buffer or discard its X8R8G8B8 (opaque alpha) semantics.
  if (&to != &back && (to.width != from.width || to.height != from.height || to.flags != from.flags || !to.texture)) {
    release(to);
    to.width = from.width;
    to.height = from.height;
    to.logical_width = from.logical_width;
    to.logical_height = from.logical_height;
    to.flags = from.flags;
    allocate(to);
  }
  copy(from, to);
}
void wgpu_w2c_host_texture_copy(struct w2c_host *, u32 destination, u32 source) {
  Target &from = target_or_back((int)source);
  if (!from.texture)
    return;
  Target &to = textures[(int)destination];
  if (to.width != from.width || to.height != from.height || format_of(to) != format_of(from) || !to.texture) {
    release(to);
    to.width = from.width;
    to.height = from.height;
    to.logical_width = from.logical_width;
    to.logical_height = from.logical_height;
    to.flags = TARGET_RENDER | (from.flags & TARGET_HALF_FLOAT);
    allocate(to);
  }
  copy(from, to);
}
void wgpu_w2c_host_back_buffer(struct w2c_host *, u32 width, u32 height) {
  Target &back = textures[0];
  release(back);
  back.logical_width = (int)width;
  back.logical_height = (int)height;
  Viewport v = wgpu_renderer_viewport(drawable_width, drawable_height);
  back.width = v.width ? v.width : (int)width;
  back.height = v.height ? v.height : (int)height;
  back.flags = TARGET_RENDER | TARGET_OPAQUE | (rtx ? TARGET_HALF_FLOAT : 0); // the back buffer is X8R8G8B8
  allocate(back);
  current_target = 0;
}
void wgpu_w2c_host_texture_create(struct w2c_host *, u32 id, u32 width, u32 height, u32 flags) {
  Target &t = textures[(int)id];
  release(t);
  t.logical_width = t.width = (int)width;
  t.logical_height = t.height = (int)height;
  t.flags = (int)flags;
  // The game's offscreen render target is its persistent ground. Rasterize it
  // at 2x the configured density, independently of the window.
  if (t.flags & TARGET_RENDER) {
    t.width *= 2;
    t.height *= 2;
  }
  allocate(t);
}
void wgpu_w2c_host_texture_upload(struct w2c_host *, u32 id, u32 texels) {
  auto it = textures.find((int)id);
  if (it == textures.end())
    return;
  Target &t = it->second;
  if (!(t.flags & TARGET_RENDER))
    texel_addresses[(int)id] = texels;
  // What the frame drew so far sampled the texture as it was.
  submit();
  // A8R8G8B8 texels are BGRA bytes, at logical size even for a denser target.
  std::vector<unsigned char> rgba((size_t)t.width * t.height * 4);
  const u8 *bgra = client_memory() + texels;
  for (int y = 0; y < t.height; ++y)
    for (int x = 0; x < t.width; ++x) {
      size_t source = ((size_t)(y * t.logical_height / t.height) * t.logical_width + x * t.logical_width / t.width) * 4;
      size_t destination = ((size_t)y * t.width + x) * 4;
      rgba[destination] = bgra[source + 2];
      rgba[destination + 1] = bgra[source + 1];
      rgba[destination + 2] = bgra[source];
      rgba[destination + 3] = bgra[source + 3];
    }
  WGPUTexelCopyTextureInfo destination = WGPU_TEXEL_COPY_TEXTURE_INFO_INIT;
  destination.texture = t.texture;
  WGPUTexelCopyBufferLayout layout = {0, (uint32_t)t.width * 4, (uint32_t)t.height};
  WGPUExtent3D extent = {(uint32_t)t.width, (uint32_t)t.height, 1};
  wgpuQueueWriteTexture(queue, &destination, rgba.data(), rgba.size(), &layout, &extent);
}
void wgpu_w2c_host_texture_release(struct w2c_host *, u32 id) {
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
    wgpuTextureViewRelease(map->second.view);
    wgpuTextureRelease(map->second.texture);
    thickness_maps.erase(map);
    forget_groups();
  }
}
void wgpu_w2c_host_render_state(struct w2c_host *, u32 state, u32 value) {
  if (state < 256)
    render_states[state] = value;
}
void wgpu_w2c_host_texture_stage_state(struct w2c_host *, u32 stage, u32 state, u32 value) {
  if (stage < STAGES && state < 32)
    stage_states[stage][state] = value;
}
void wgpu_w2c_host_set_texture(struct w2c_host *, u32 stage, u32 id) {
  if (stage < STAGES)
    bound[stage] = (int)id;
}
void wgpu_w2c_host_set_render_target(struct w2c_host *, u32 id) { current_target = (int)id; }
void wgpu_w2c_host_clear(struct w2c_host *, u32 color) {
  Target &t = drawing_target(current_target);
  WGPUColor clear = {(color >> 16 & 255) / 255.0, (color >> 8 & 255) / 255.0, (color & 255) / 255.0,
                     t.flags & TARGET_OPAQUE ? 1.0 : (color >> 24) / 255.0};
  begin_pass(t, &clear);
}
void wgpu_w2c_host_draw(struct w2c_host *, u32 primitive, u32 vertices, u32 vertex_count, u32 indices,
                        u32 primitive_count) {
  int index_count = primitive == 4 ? primitive_count * 3 : primitive == 5 || primitive == 6 ? primitive_count + 2
                    : primitive == 2 ? primitive_count * 2 : primitive == 3 ? primitive_count + 1 : primitive_count;
  // WebGPU has no fans: their triangles as a list.
  std::vector<unsigned short> fan;
  const unsigned short *index_data = indices ? (const unsigned short *)(client_memory() + indices) : nullptr;
  if (primitive == 6) {
    for (int i = 1; i + 1 < index_count; ++i)
      for (int corner : {0, i, i + 1})
        fan.push_back(index_data ? index_data[corner] : (unsigned short)corner);
    index_data = fan.data();
    index_count = (int)fan.size();
  }
  static const WGPUPrimitiveTopology topologies[] = {
      WGPUPrimitiveTopology_PointList, WGPUPrimitiveTopology_PointList, WGPUPrimitiveTopology_LineList,
      WGPUPrimitiveTopology_LineStrip, WGPUPrimitiveTopology_TriangleList, WGPUPrimitiveTopology_TriangleStrip,
      WGPUPrimitiveTopology_TriangleList};
  WGPUPrimitiveTopology topology = primitive < 7 ? topologies[primitive] : WGPUPrimitiveTopology_TriangleList;
  uint64_t vertex_bytes = (uint64_t)vertex_count * 28, index_bytes = index_data ? (uint64_t)index_count * 2 : 0;
  if (!fits(vertex_stream, vertex_bytes) || !fits(index_stream, index_bytes + 3) ||
      !fits(uniform_stream, creature_lit.frag->uniform_size + 512 + creature_lit.vert->uniform_size))
    submit();

  Target &t = drawing_target(current_target);
  pass_into(t);
  bool lit = rtx && world && material && (material != HOST_PASS_PLAYERS || light_count);
  Program &program = !lit                           ? classic
                     : material == HOST_PASS_PLAYERS ? player_lit
                     : material == MATERIAL_BONUS    ? bonus_lit
                                                     : creature_lit;
  if (lit) {
    Uniforms vertex(*program.vert), fragment(*program.frag);
    vertex.v2("target_size", (float)t.logical_width, (float)t.logical_height).v2("camera", scene_camera[0], scene_camera[1]);
    fragment.v4("colDiffuse", 1, 1, 1, 1).i("u_count", light_count).f("u_ambient", 0.6f);
    fragment.set("u_occlusion_grid", occlusion_grid, 16).f("u_occlusion_cell_size", occlusion_cell);
    fragment.i("u_dynamic_shadows", dynamic_shadows);
    fragment.i("u_pass", bonus_emblem).set("u_grid", bonus_grid, 8).set("u_shell_center", bonus_center, 8);
    fragment.set("u_pos", light_pos, light_count * 16).set("u_rgb", light_rgb, light_count * 16);
    fragment.set("u_dir", light_dir, light_count * 16).set("u_response", light_response, light_count * 16);
    auto it = textures.find(bound[0]);
    bool present = bound[0] && it != textures.end() && it->second.texture;
    WGPUSampler atlas_sampler = sampler(stage_states[0][TSS_ADDRESSU], stage_states[0][TSS_ADDRESSV],
                                        stage_states[0][TSS_MAGFILTER] >= 2, stage_states[0][TSS_MINFILTER] >= 2);
    WGPUTextureView thickness = material == HOST_PASS_CREATURES && present ? thickness_map(bound[0]) : blank_view;
    wgpuRenderPassEncoderSetPipeline(pass, pipeline(program, device_output(t, topology)));
    bind(program,
         fragment_group(program, {{"texture0", present ? it->second.view : blank_view, atlas_sampler},
                                  {"u_thickness", thickness, linear_clamp()},
                                  {"u_occlusion_tex", occlusion_grid[2] ? occlusion_view : blank_view, nearest_clamp()}}),
         &vertex, &fragment);
  }
  Uniforms vertex(*classic.vert), fragment(*classic.frag);
  vertex.v2("target_size", (float)t.logical_width, (float)t.logical_height);
  int has[STAGES], filters[STAGES], cop[STAGES], ca1[STAGES], ca2[STAGES], aop[STAGES], aa1[STAGES], aa2[STAGES];
  Input inputs[STAGES];
  for (int s = 0; s < STAGES; ++s) {
    auto it = textures.find(bound[s]);
    bool present = bound[s] && it != textures.end() && it->second.texture;
    has[s] = present;
    bool artwork = present && !(it->second.flags & TARGET_RENDER);
    filters[s] = artwork && stage_states[s][TSS_MINFILTER] >= 2 && stage_states[s][TSS_MAGFILTER] >= 2 ? 1 : 0;
    if (artwork && current_target && stage_states[s][TSS_TERRAIN_ART])
      filters[s] = 2;
    cop[s] = (int)stage_states[s][TSS_COLOROP];
    ca1[s] = (int)stage_states[s][TSS_COLORARG1];
    ca2[s] = (int)stage_states[s][TSS_COLORARG2];
    aop[s] = (int)stage_states[s][TSS_ALPHAOP];
    aa1[s] = (int)stage_states[s][TSS_ALPHAARG1];
    aa2[s] = (int)stage_states[s][TSS_ALPHAARG2];
    inputs[s] = {s ? "texture1" : "texture0", present ? it->second.view : blank_view,
                 sampler(stage_states[s][TSS_ADDRESSU], stage_states[s][TSS_ADDRESSV], stage_states[s][TSS_MAGFILTER] >= 2,
                         stage_states[s][TSS_MINFILTER] >= 2)};
  }
  fragment.i2("has_texture", has).i2("reconstruction", filters).i2("color_op", cop).i2("color_arg1", ca1);
  fragment.i2("color_arg2", ca2).i2("alpha_op", aop).i2("alpha_arg1", aa1).i2("alpha_arg2", aa2);
  unsigned f = render_states[RS_TEXTUREFACTOR];
  fragment.v4("factor", (f >> 16 & 255) / 255.0f, (f >> 8 & 255) / 255.0f, (f & 255) / 255.0f, (f >> 24) / 255.0f);
  fragment.i("alpha_test", render_states[RS_ALPHATESTENABLE] != 0);
  fragment.f("alpha_ref", (float)(render_states[RS_ALPHAREF] & 255));
  fragment.i("alpha_func", (int)render_states[RS_ALPHAFUNC]);

  if (!lit) {
    wgpuRenderPassEncoderSetPipeline(pass, pipeline(classic, device_output(t, topology)));
    bind(classic, fragment_group(classic, {inputs[0], inputs[1]}), &vertex, &fragment);
  }
  uint64_t vertex_at = put(vertex_stream, client_memory() + vertices, vertex_bytes);
  wgpuRenderPassEncoderSetVertexBuffer(pass, 0, vertex_stream.buffer, vertex_at, vertex_bytes);
  if (index_data) {
    uint64_t index_at = put(index_stream, index_data, index_bytes);
    wgpuRenderPassEncoderSetIndexBuffer(pass, index_stream.buffer, WGPUIndexFormat_Uint16, index_at, (index_bytes + 3) & ~3ull);
    wgpuRenderPassEncoderDrawIndexed(pass, index_count, 1, 0, 0, 0);
  } else {
    wgpuRenderPassEncoderDraw(pass, index_count, 1, 0, 0);
  }
}
void wgpu_w2c_host_beam(struct w2c_host *, u32 corners, f32 length, f32 step, u32 color) {
  if (!rtx)
    return;
  if (!fits(vertex_stream, 64) || !fits(uniform_stream, 512))
    submit();
  Target &t = drawing_target(current_target);
  pass_into(t);
  Uniforms vertex(*beam.vert), fragment(*beam.frag);
  vertex.v2("target_size", (float)t.logical_width, (float)t.logical_height).f("beam_length", length).f("beam_step", step);
  vertex.v4("beam_color", (color >> 16 & 255) / 255.0f, (color >> 8 & 255) / 255.0f, (color & 255) / 255.0f,
            (color >> 24) / 255.0f);
  fragment.v4("colDiffuse", 1, 1, 1, 1);
  wgpuRenderPassEncoderSetPipeline(pass, pipeline(beam, device_output(t, WGPUPrimitiveTopology_TriangleStrip)));
  bind(beam, fragment_group(beam, {}), &vertex, &fragment);
  // The quad's corners run around it; a strip takes them as 0, 1, 3, 2.
  const float *c = (const float *)(client_memory() + corners);
  static const int order[4] = {0, 1, 3, 2};
  float strip[16];
  for (int i = 0; i < 4; ++i)
    memcpy(strip + i * 4, c + order[i] * 4, 16);
  uint64_t at = put(vertex_stream, strip, sizeof strip);
  wgpuRenderPassEncoderSetVertexBuffer(pass, 0, vertex_stream.buffer, at, sizeof strip);
  wgpuRenderPassEncoderDraw(pass, 4, 1, 0, 0);
}
void wgpu_w2c_host_scene(struct w2c_host *, u32 camera, u32 lights, u32 count) {
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
void wgpu_w2c_host_occlusion(struct w2c_host *, u32 grid, u32 values, u32 count) {
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
    if (occlusion_texture) {
      wgpuTextureViewRelease(occlusion_view);
      wgpuTextureRelease(occlusion_texture);
      forget_groups();
    }
    WGPUTextureDescriptor descriptor = WGPU_TEXTURE_DESCRIPTOR_INIT;
    descriptor.size = {OCCLUSION_WIDTH, (uint32_t)occlusion_rows, 1};
    descriptor.format = WGPUTextureFormat_RGBA32Float;
    descriptor.usage = WGPUTextureUsage_TextureBinding | WGPUTextureUsage_CopyDst;
    occlusion_texture = wgpuDeviceCreateTexture(device, &descriptor);
    occlusion_view = wgpuTextureCreateView(occlusion_texture, nullptr);
  }
  // Earlier draws this frame read the grid as it was.
  submit();
  std::vector<float> texels((size_t)rows * OCCLUSION_WIDTH * 4);
  memcpy(texels.data(), client_memory() + values, (size_t)count * 4);
  WGPUTexelCopyTextureInfo destination = WGPU_TEXEL_COPY_TEXTURE_INFO_INIT;
  destination.texture = occlusion_texture;
  WGPUTexelCopyBufferLayout layout = {0, OCCLUSION_WIDTH * 16, (uint32_t)rows};
  WGPUExtent3D extent = {OCCLUSION_WIDTH, (uint32_t)rows, 1};
  wgpuQueueWriteTexture(queue, &destination, texels.data(), texels.size() * 4, &layout, &extent);
}
void wgpu_w2c_host_bonus(struct w2c_host *, u32 emblem, f32 grid_x, f32 grid_y, f32 center_x, f32 center_y) {
  material = MATERIAL_BONUS;
  bonus_emblem = (int)emblem;
  bonus_grid[0] = grid_x, bonus_grid[1] = grid_y;
  bonus_center[0] = center_x, bonus_center[1] = center_y;
}
void wgpu_w2c_host_render_pass(struct w2c_host *, u32 pass_kind) {
  if (pass_kind >= HOST_PASS_CREATURES) {
    material = pass_kind == HOST_PASS_SPRITES ? 0 : (int)pass_kind;
    return;
  }
  Target &back = textures[0];
  if (!rtx || !back.texture)
    return;
  if (pass_kind == HOST_PASS_WORLD_BEGIN) { // The world goes over what the frame drew so far.
    if (hdr.width != back.width || hdr.height != back.height || !hdr.texture) {
      release(hdr);
      hdr.width = back.width;
      hdr.height = back.height;
      hdr.flags = back.flags | TARGET_HALF_FLOAT;
      allocate(hdr);
    }
    hdr.logical_width = back.logical_width;
    hdr.logical_height = back.logical_height;
    copy(back, hdr);
    world = true;
  } else if (pass_kind == HOST_PASS_WORLD_END && world) {
    world = false;
    material = 0;
    if (!fits(uniform_stream, 512))
      submit();
    begin_pass(back, nullptr);
    Output o;
    o.format = format_of(back);
    o.mask = 7;
    Uniforms fragment(*tonemap.frag);
    fragment.v4("colDiffuse", 1, 1, 1, 1).f("u_edr_headroom", edr_headroom);
    wgpuRenderPassEncoderSetPipeline(pass, pipeline(tonemap, o));
    bind(tonemap, fragment_group(tonemap, {{"texture0", hdr.view, nearest_clamp()}}), nullptr, &fragment);
    wgpuRenderPassEncoderDraw(pass, 4, 1, 0, 0);
    end_pass();
  }
}
void wgpu_w2c_host_gamma_ramp(struct w2c_host *, u32 red, u32 green, u32 blue) {
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
  WGPUTexelCopyTextureInfo destination = WGPU_TEXEL_COPY_TEXTURE_INFO_INIT;
  destination.texture = gamma_texture;
  WGPUTexelCopyBufferLayout layout = {0, 256 * 4, 1};
  WGPUExtent3D extent = {256, 1, 1};
  wgpuQueueWriteTexture(queue, &destination, ramp, sizeof ramp, &layout, &extent);
}
}
#endif
