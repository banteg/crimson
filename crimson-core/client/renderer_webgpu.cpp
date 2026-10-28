// The browser's WebGPU renderer: the same Direct3D 8 subset as renderer.cpp, and
// the RTX mode, whose world draws past white and reaches HDR displays through a
// half-float canvas with extended tone mapping. The page gets the device before
// the module starts (shell.html); renderer_select.cpp picks this renderer then.
// The shaders are renderer.cpp's GLSL translated to WGSL (client/shaders.py).
// Targets keep renderer.cpp's orientation: row 0 is the image's top row.
#ifdef __EMSCRIPTEN__
#include "../game/effect_vertices.h"
#include "client.h"
#include "device_states.h"
#include "ground_visibility.h"
#include "ice_surface.h"
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
// The freeze ice's surface (HOST_PASS_ICE_*), as in renderer.cpp.
WGPUTexture ice_texture;
WGPUTextureView ice_view;

WGPUStringView text(const char *s) { return WGPUStringView{s, strlen(s)}; }
// The RTX ground's float surface: 32-bit where the device filters and blends it
// (shell.html asks for both), else half floats.
WGPUTextureFormat float_format() {
  static const bool full = wgpuDeviceHasFeature(device, WGPUFeatureName_Float32Filterable) &&
                           wgpuDeviceHasFeature(device, WGPUFeatureName_Float32Blendable);
  return full ? WGPUTextureFormat_RGBA32Float : WGPUTextureFormat_RGBA16Float;
}
WGPUTextureFormat format_of(const Target &t) {
  return t.flags & TARGET_FLOAT        ? float_format()
         : t.flags & TARGET_HALF_FLOAT ? WGPUTextureFormat_RGBA16Float
                                       : WGPUTextureFormat_RGBA8Unorm;
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
// CENTERED_VERTICES: the device's vertices, then their quad centers (quad_centers) as a second buffer.
enum VertexInput { NO_VERTICES, DEVICE_VERTICES, BEAM_CORNERS, CENTERED_VERTICES };

struct Program {
  const WgslStage *vert, *frag;
  VertexInput input;
  WGPUShaderModule vert_module, frag_module;
  WGPUBindGroupLayout layouts[2];
  WGPUPipelineLayout layout;
  WGPUBindGroup vertex_group; // group 1 of a vertex stage with a uniform block alone
  std::unordered_map<uint64_t, WGPURenderPipeline> pipelines;
  std::unordered_map<uint64_t, WGPUBindGroup> groups;        // group 0, by its textures and samplers
  std::unordered_map<uint64_t, WGPUBindGroup> vertex_groups; // group 1 of a vertex stage with textures, likewise
};
Program classic{&WGSL_CLASSIC_VERT, &WGSL_CLASSIC_FRAG, DEVICE_VERTICES};
Program present_program{&WGSL_PRESENT_VERT, &WGSL_PRESENT_FRAG, NO_VERTICES};
Program blit{&WGSL_FULLSCREEN_VERT, &WGSL_BLIT_FRAG, NO_VERTICES};
Program tonemap{&WGSL_FULLSCREEN_VERT, &WGSL_HDR_TONEMAP_FRAG, NO_VERTICES};
Program beam{&WGSL_BEAM_VERT, &WGSL_BEAM_FRAG, BEAM_CORNERS};
Program effect{&WGSL_EFFECT_VERT, &WGSL_EFFECT_FRAG, DEVICE_VERTICES};
Program creature_lit{&WGSL_CREATURE_LIT_VERT, &WGSL_CREATURE_FRAG, CENTERED_VERTICES};
Program player_lit{&WGSL_CREATURE_VERT, &WGSL_PLAYER_FRAG, DEVICE_VERTICES};
Program bonus_lit{&WGSL_CREATURE_VERT, &WGSL_BONUS_FRAG, DEVICE_VERTICES};
Program ground_lit{&WGSL_CREATURE_VERT, &WGSL_GROUND_LIT_FRAG, DEVICE_VERTICES};
Program ground_beam_vis{&WGSL_GROUND_VISIBILITY_VERT, &WGSL_GROUND_BEAM_VIS_FRAG, NO_VERTICES};
Program ground_stamp{&WGSL_CREATURE_VERT, &WGSL_GROUND_STAMP_FRAG, DEVICE_VERTICES};
Program ground_fill{&WGSL_FULLSCREEN_VERT, &WGSL_GROUND_STAMP_FRAG, NO_VERTICES};
Program smoke_solver{&WGSL_SMOKE_RECT_VERT, &WGSL_SMOKE_SOLVER_FRAG, NO_VERTICES};
Program smoke_splat{&WGSL_SMOKE_RECT_VERT, &WGSL_SMOKE_SPLAT_FRAG, NO_VERTICES};
Program smoke_impulse{&WGSL_SMOKE_RECT_VERT, &WGSL_SMOKE_IMPULSE_FRAG, NO_VERTICES};
Program smoke_display{&WGSL_SMOKE_FIELD_VERT, &WGSL_SMOKE_FRAG, NO_VERTICES};
Program heat_body{&WGSL_CREATURE_VERT, &WGSL_HEAT_BODY_FRAG, DEVICE_VERTICES};
Program heat_stamp{&WGSL_CREATURE_VERT, &WGSL_HEAT_STAMP_FRAG, DEVICE_VERTICES};
Program heat_trail_program{&WGSL_CREATURE_VERT, &WGSL_HEAT_TRAIL_LIT_FRAG, DEVICE_VERTICES};
Program contact_glow{&WGSL_CREATURE_VERT, &WGSL_CONTACT_GLOW_FRAG, DEVICE_VERTICES};
Program pressure_fronts_program{&WGSL_FULLSCREEN_VERT, &WGSL_PRESSURE_LIT_FRAG, NO_VERTICES};
// The explosions' pressure fronts (host_pressure), as in renderer.cpp.
std::vector<float> pressure_fronts;
Target pressured;
// Monster Vision's trail buffer and the run's clock it last faded at, as in renderer.cpp.
const float HEAT_TRAIL_SCALE = 0.5f, HEAT_HALF_LIFE_S = 0.3f, HEAT_MAX_GAP_S = 1;
Target heat_trail;
float heat_seconds = -1;

// RTX lighting, as in renderer.cpp: the world's lights and camera, the batch
// being drawn, a bonus draw's own material, and each artwork's texels in the
// module for creature thickness.
enum { MAX_LIGHTS = 32 };
int material;
float scene_camera[2];
GroundVisibility ground_visibility;
bool visibility_dirty = true;
float light_pos[MAX_LIGHTS * 4], light_rgb[MAX_LIGHTS * 4], light_dir[MAX_LIGHTS * 4], light_response[MAX_LIGHTS * 4];
int light_count;
int bonus_emblem;
float bonus_grid[2], bonus_center[2];
// What the ground takes beyond them, as in renderer.cpp.
float scene_seconds, ground_size[2], beam_gain[2];
float ground_dir[MAX_LIGHTS * 4], light_tail[MAX_LIGHTS], beam_shape[MAX_LIGHTS * 4];
bool beam_lights;
std::unordered_map<int, u32> texel_addresses;
struct Thickness {
  WGPUTexture texture;
  WGPUTextureView view;
};
std::unordered_map<int, Thickness> thickness_maps, heat_density_maps;
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
  if (p.vert->uniform_size && p.vert->binding_count == 1) {
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
  // Alpha's own factors (the RTX ground's coverage), or the color's.
  WGPUBlendFactor alpha_src = WGPUBlendFactor_Undefined, alpha_dst = WGPUBlendFactor_Undefined;
  uint64_t key() const {
    return (uint64_t)format | (uint64_t)blend << 8 | (uint64_t)src << 9 | (uint64_t)dst << 17 | (uint64_t)op << 25 |
           (uint64_t)mask << 33 | (uint64_t)topology << 37 | (uint64_t)alpha_src << 41 | (uint64_t)alpha_dst << 49;
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
  WGPUVertexAttribute center = WGPU_VERTEX_ATTRIBUTE_INIT;
  WGPUVertexBufferLayout buffers[2] = {WGPU_VERTEX_BUFFER_LAYOUT_INIT, WGPU_VERTEX_BUFFER_LAYOUT_INIT};
  WGPUVertexBufferLayout &buffer = buffers[0];
  buffer.stepMode = WGPUVertexStepMode_Vertex;
  buffer.attributes = attributes;
  if (p.input == DEVICE_VERTICES || p.input == CENTERED_VERTICES) {
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
    if (p.input == CENTERED_VERTICES) {
      center.format = WGPUVertexFormat_Float32x2;
      center.shaderLocation = 3;
      buffers[1].stepMode = WGPUVertexStepMode_Vertex;
      buffers[1].arrayStride = 8;
      buffers[1].attributeCount = 1;
      buffers[1].attributes = &center;
    }
  } else if (p.input == BEAM_CORNERS) {
    attributes[0].format = WGPUVertexFormat_Float32x4;
    attributes[0].shaderLocation = 0;
    buffer.arrayStride = 16;
    buffer.attributeCount = 1;
  }
  WGPUBlendState blend = WGPU_BLEND_STATE_INIT;
  blend.color.operation = blend.alpha.operation = o.op;
  blend.color.srcFactor = o.src;
  blend.color.dstFactor = o.dst;
  blend.alpha.srcFactor = o.alpha_src ? o.alpha_src : o.src;
  blend.alpha.dstFactor = o.alpha_dst ? o.alpha_dst : o.dst;
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
  descriptor.vertex.bufferCount = p.input == NO_VERTICES ? 0 : p.input == CENTERED_VERTICES ? 2 : 1;
  descriptor.vertex.buffers = buffers;
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

// A stage's group: its uniforms, then each texture and its sampler, by name.
struct Input {
  const char *name;
  WGPUTextureView view;
  WGPUSampler sampler;
};
WGPUBindGroup stage_group(const WgslStage &stage, WGPUBindGroupLayout layout,
                          std::unordered_map<uint64_t, WGPUBindGroup> &cache, std::initializer_list<Input> inputs) {
  uint64_t key = 0;
  for (const Input &in : inputs)
    key = key * 1000003 ^ (uintptr_t)in.view ^ (uint64_t)(uintptr_t)in.sampler << 32;
  auto it = cache.find(key);
  if (it != cache.end())
    return it->second;
  std::vector<WGPUBindGroupEntry> entries;
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
  descriptor.layout = layout;
  descriptor.entryCount = entries.size();
  descriptor.entries = entries.data();
  return cache[key] = wgpuDeviceCreateBindGroup(device, &descriptor);
}
// Group 0: the fragment stage's.
WGPUBindGroup fragment_group(Program &p, std::initializer_list<Input> inputs) {
  return stage_group(*p.frag, p.layouts[0], p.groups, inputs);
}
// Group 1 of a vertex stage with textures.
WGPUBindGroup vertex_group(Program &p, std::initializer_list<Input> inputs) {
  return stage_group(*p.vert, p.layouts[1], p.vertex_groups, inputs);
}

// Bind a program's groups with its uniform blocks, written to the stream.
// A stage without a uniform block (the heat bodies' fragment) takes no uniforms;
// a vertex stage with textures takes its own group (vertex_group).
void bind(Program &p, WGPUBindGroup group, const Uniforms *vertex, const Uniforms *fragment,
          WGPUBindGroup vertex_textures = nullptr) {
  if (!p.frag->uniform_size)
    fragment = nullptr;
  if (!p.vert->uniform_size)
    vertex = nullptr;
  uint32_t offset = fragment ? (uint32_t)put(uniform_stream, fragment->data, p.frag->uniform_size) : 0;
  wgpuRenderPassEncoderSetBindGroup(pass, 0, group, fragment ? 1 : 0, &offset);
  if (vertex) {
    uint32_t vertex_offset = (uint32_t)put(uniform_stream, vertex->data, p.vert->uniform_size);
    wgpuRenderPassEncoderSetBindGroup(pass, 1, vertex_textures ? vertex_textures : p.vertex_group, 1, &vertex_offset);
  }
}

// Everything bound to a texture view goes when the texture does.
void forget_groups() {
  for (Program *p : {&classic, &present_program, &blit, &tonemap, &beam, &effect, &creature_lit, &player_lit, &bonus_lit,
                     &ground_lit, &ground_beam_vis, &ground_stamp, &ground_fill,
                     &smoke_solver, &smoke_splat, &smoke_impulse, &smoke_display,
                     &heat_body, &heat_stamp, &heat_trail_program, &contact_glow, &pressure_fronts_program}) {
    for (auto *cache : {&p->groups, &p->vertex_groups}) {
      for (auto &[key, group] : *cache)
        wgpuBindGroupRelease(group);
      cache->clear();
    }
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

// While the RTX world draws, the back buffer's draws go to the HDR target.
Target &drawing_target(int id) {
  Target &t = target_or_back(id);
  return world && &t == &textures[0] ? world_kept() ? hdr : discarded : t;
}
// Whether a draw into `t` enters the world's linear light.
bool in_world(const Target &t) { return &t == &hdr || &t == &discarded; }

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

WGPUTexture small_texture(int width, const unsigned char *rgba, WGPUTextureView &view, int height = 1) {
  WGPUTextureDescriptor descriptor = WGPU_TEXTURE_DESCRIPTOR_INIT;
  descriptor.size = {(uint32_t)width, (uint32_t)height, 1};
  descriptor.format = WGPUTextureFormat_RGBA8Unorm;
  descriptor.usage = WGPUTextureUsage_TextureBinding | WGPUTextureUsage_CopyDst;
  WGPUTexture texture = wgpuDeviceCreateTexture(device, &descriptor);
  view = wgpuTextureCreateView(texture, nullptr);
  WGPUTexelCopyTextureInfo destination = WGPU_TEXEL_COPY_TEXTURE_INFO_INIT;
  destination.texture = texture;
  WGPUTexelCopyBufferLayout layout = {0, (uint32_t)width * 4, (uint32_t)height};
  WGPUExtent3D extent = {(uint32_t)width, (uint32_t)height, 1};
  wgpuQueueWriteTexture(queue, &destination, rgba, (size_t)width * height * 4, &layout, &extent);
  return texture;
}

// Transmission part sizes or Monster Vision's continuous silhouette density,
// made once on first use, as in renderer.cpp and creature_translucency.py.
WGPUTextureView shape_map(int id, bool heat = false) {
  auto &maps = heat ? heat_density_maps : thickness_maps;
  auto made = maps.find(id);
  if (made != maps.end())
    return made->second.view;
  auto t = textures.find(id);
  auto texels = texel_addresses.find(id);
  if ((!light_count && !heat) || t == textures.end() || texels == texel_addresses.end())
    return blank_view;
  int width = t->second.logical_width, height = t->second.logical_height;
  const auto *pixels = client_memory() + texels->second;
  std::vector<unsigned char> sizes =
      heat ? renderer_heat_density(pixels, width, height) : renderer_thickness(pixels, width, height);
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
  return (maps[id] = map).view;
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
  for (Program *p : {&classic, &present_program, &blit, &tonemap, &beam, &effect, &creature_lit, &player_lit, &bonus_lit,
                     &ground_lit, &ground_beam_vis, &ground_stamp, &ground_fill,
                     &smoke_solver, &smoke_splat, &smoke_impulse, &smoke_display,
                     &heat_body, &heat_stamp, &heat_trail_program, &contact_glow, &pressure_fronts_program})
    create(*p);
  const unsigned char white[4] = {255, 255, 255, 255};
  blank = small_texture(1, white, blank_view);
  ice_texture = small_texture(ICE_SURFACE_WIDTH, ice_surface, ice_view, ICE_SURFACE_HEIGHT);
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

// A draw's geometry in the streams, drawn into each pass that takes it.
struct Geometry {
  WGPUPrimitiveTopology topology;
  uint64_t vertex_at, vertex_bytes, index_at = 0, index_bytes = 0, center_at = 0, center_bytes = 0;
  int index_count;
};
void draw_geometry(const Geometry &g) {
  wgpuRenderPassEncoderSetVertexBuffer(pass, 0, vertex_stream.buffer, g.vertex_at, g.vertex_bytes);
  if (g.center_bytes)
    wgpuRenderPassEncoderSetVertexBuffer(pass, 1, vertex_stream.buffer, g.center_at, g.center_bytes);
  if (g.index_bytes) {
    wgpuRenderPassEncoderSetIndexBuffer(pass, index_stream.buffer, WGPUIndexFormat_Uint16, g.index_at,
                                        (g.index_bytes + 3) & ~3ull);
    wgpuRenderPassEncoderDrawIndexed(pass, g.index_count, 1, 0, 0, 0);
  } else {
    wgpuRenderPassEncoderDraw(pass, g.index_count, 1, 0, 0);
  }
}

// The circle the device shades itself (host_circle), or none: classic.frag's circle and circle_uv.
static float circle[8];
// The device's own shading of the next draw into `t`, in the open pass.
void bind_classic(const Target &t, WGPUPrimitiveTopology topology) {
  Uniforms vertex(*classic.vert), fragment(*classic.frag);
  vertex.v2("target_size", (float)t.logical_width, (float)t.logical_height);
  vertex.i("in_world", in_world(t));
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
  fragment.i("alpha_test", render_states[RS_ALPHATESTENABLE] != 0 && !(in_world(t) && additive_emission(render_states)));
  fragment.f("alpha_ref", (float)(render_states[RS_ALPHAREF] & 255));
  fragment.i("alpha_func", (int)render_states[RS_ALPHAFUNC]);
  fragment.i("in_world", in_world(t));
  fragment.i("glint", in_world(t) && material == HOST_PASS_GLINT);
  fragment.set("circle", circle, 16).set("circle_uv", circle + 4, 16);
  wgpuRenderPassEncoderSetPipeline(pass, pipeline(classic, device_output(t, topology)));
  bind(classic, fragment_group(classic, {inputs[0], inputs[1]}), &vertex, &fragment);
}

// --- The RTX ground (render/rtx/materials.py), as in renderer.cpp -----------------
struct Ground {
  Target substrate, coverage, surface;
  float epoch = 0;
};
std::unordered_map<int, Ground> grounds;
int ground_kind = HOST_GROUND_END;
float ground_seconds;

void drop_ground(int id) {
  auto it = grounds.find(id);
  if (it == grounds.end())
    return;
  release(it->second.substrate);
  release(it->second.coverage);
  release(it->second.surface);
  grounds.erase(it);
}

// A ground pass over a whole companion: the stamp shader's `kind` and `pass`
// over `source`, into `into` with `o`'s blend.
void fill_ground(Target &into, WGPUTextureView source, int kind, int pass_id, float wetness, Output o) {
  pass_into(into);
  o.format = format_of(into);
  Uniforms fragment(*ground_fill.frag);
  fragment.i("u_kind", kind).i("u_pass", pass_id).f("u_wetness", wetness);
  wgpuRenderPassEncoderSetPipeline(pass, pipeline(ground_fill, o));
  bind(ground_fill, fragment_group(ground_fill, {{"texture0", source, linear_clamp()}}), nullptr, &fragment);
  wgpuRenderPassEncoderDraw(pass, 4, 1, 0, 0);
}

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
  copy(albedo, g.substrate);
  WGPUColor none = {0, 0, 0, 0}, terrain = {10 / 255.0, 0, 0, 115 / 255.0};
  begin_pass(g.coverage, &none);
  begin_pass(g.surface, &terrain);
  fill_ground(g.surface, g.substrate.view, 0, 0, 0, Output{});
  return g;
}

void rebase_wetness(Ground &g, float epoch) {
  Output o;
  o.blend = true, o.src = WGPUBlendFactor_Zero, o.dst = WGPUBlendFactor_Src, o.mask = WGPUColorWriteMask_Green;
  fill_ground(g.surface, blank_view, 0, 3, expf((g.epoch - epoch) / 45), o);
  g.epoch = epoch;
}

void stamp_ground(Ground &g, int kind, const Geometry &geometry) {
  if (ground_seconds - g.epoch > 180)
    rebase_wetness(g, ground_seconds);
  auto it = textures.find(bound[0]);
  bool present = bound[0] && it != textures.end() && it->second.texture;
  Input atlas = {"texture0", present ? it->second.view : blank_view,
                 sampler(stage_states[0][TSS_ADDRESSU], stage_states[0][TSS_ADDRESSV], stage_states[0][TSS_MAGFILTER] >= 2,
                         stage_states[0][TSS_MINFILTER] >= 2)};
  bool blood = kind == HOST_GROUND_BLOOD;
  for (int pass_id = 0; pass_id < (blood ? 2 : 3); ++pass_id) {
    Target &into = pass_id ? g.surface : g.coverage;
    pass_into(into);
    Output o;
    o.format = format_of(into);
    o.topology = geometry.topology;
    o.blend = true;
    o.dst = WGPUBlendFactor_OneMinusSrcAlpha;
    if (pass_id == 0) {
      // RGB weighs the materials alpha-over; A is ice coverage, which every later material occludes.
      o.src = WGPUBlendFactor_SrcAlpha;
      o.alpha_src = kind == HOST_GROUND_ICE ? WGPUBlendFactor_One : WGPUBlendFactor_Zero;
      o.alpha_dst = WGPUBlendFactor_OneMinusSrcAlpha;
    } else if (pass_id == 1) {
      o.src = blood ? WGPUBlendFactor_One : WGPUBlendFactor_SrcAlpha;
      o.mask = (blood ? 0 : WGPUColorWriteMask_Red) | WGPUColorWriteMask_Green | WGPUColorWriteMask_Blue;
    } else {
      o.src = WGPUBlendFactor_One;
      o.mask = WGPUColorWriteMask_Alpha;
    }
    Uniforms vertex(*ground_stamp.vert), fragment(*ground_stamp.frag);
    vertex.v2("target_size", (float)into.logical_width, (float)into.logical_height);
    fragment.i("u_kind", kind).i("u_pass", pass_id).f("u_wetness", expf((ground_seconds - g.epoch) / 45));
    wgpuRenderPassEncoderSetPipeline(pass, pipeline(ground_stamp, o));
    bind(ground_stamp, fragment_group(ground_stamp, {atlas}), &vertex, &fragment);
    draw_geometry(geometry);
  }
}

// Vertices the host makes, in the device's layout (x, y, z, rhw, D3DCOLOR, u, v).
struct HostVertex {
  float x, y, z, rhw;
  u32 color;
  float u, v;
};

// The sources' visibility over the world in view (ground_visibility.glsl), in
// world texels independent of the display: a group of four sources per RGBA
// texel, four groups a row in one atlas, which the ground reads instead of
// walking the body grid per pixel.
enum { BEAM_VISIBILITY_ROWS = MAX_LIGHTS / 16 };
Target beam_vis;

// The stream space `groups` atlas draws take: each block at the stream's alignment.
uint64_t visibility_uniforms(int groups) {
  auto aligned = [](uint64_t size) {
    return (size + uniform_stream.alignment - 1) / uniform_stream.alignment * uniform_stream.alignment;
  };
  return groups * (aligned(ground_beam_vis.frag->uniform_size) + aligned(ground_beam_vis.vert->uniform_size));
}

// Prepare the color-independent masks before the world's HDR pass opens. A
// late scene/occlusion import can also rebuild them before the next ground draw.
void prepare_ground_visibility(int view_width, int view_height) {
  visibility_dirty = false;
  ground_visibility.prepare(scene_camera[0], scene_camera[1], (float)view_width, (float)view_height, light_count,
                            dynamic_shadows && occlusion_grid[2] > 0 && ground_size[0] > 0 && ground_size[1] > 0);
  const GroundVisibility &v = ground_visibility;
  if (!v.count)
    return;
  int groups = (v.count + 3) / 4;
  if (!fits(uniform_stream, visibility_uniforms(groups)))
    submit();
  if (beam_vis.width != 4 * v.width || beam_vis.height != BEAM_VISIBILITY_ROWS * v.height) {
    release(beam_vis);
    beam_vis.width = beam_vis.logical_width = 4 * v.width;
    beam_vis.height = beam_vis.logical_height = BEAM_VISIBILITY_ROWS * v.height;
    beam_vis.flags = TARGET_RENDER | TARGET_HALF_FLOAT;
    allocate(beam_vis);
  }
  WGPUColor white = {1, 1, 1, 1};
  begin_pass(beam_vis, &white);
  Output o;
  o.format = format_of(beam_vis);
  wgpuRenderPassEncoderSetPipeline(pass, pipeline(ground_beam_vis, o));
  Uniforms vertex(*ground_beam_vis.vert), fragment(*ground_beam_vis.frag);
  vertex.set("u_visibility_world", v.rect, 16).set("u_ground_size", ground_size, 8);
  fragment.set("u_ground_size", ground_size, 8).i("u_spec_light_count", light_count).i("u_has_beam_lights", beam_lights);
  fragment.set("u_spec_pos", light_pos, light_count * 16).set("u_spec_color", light_rgb, light_count * 16);
  fragment.set("u_spec_dir", ground_dir, light_count * 16).set("u_spec_response", light_response, light_count * 16);
  fragment.set("u_beam_shape", beam_shape, light_count * 16);
  fragment.set("u_occlusion_grid", occlusion_grid, 16).f("u_occlusion_cell_size", occlusion_cell);
  WGPUBindGroup group_inputs = fragment_group(ground_beam_vis, {{"u_occlusion_tex", occlusion_view, nearest_clamp()}});
  for (int group = 0; group < groups; ++group) {
    auto bounds = v.bounds(group, light_pos, ground_dir, light_rgb, light_response, beam_shape, beam_lights);
    if (!bounds[2] || !bounds[3]) continue;
    wgpuRenderPassEncoderSetScissorRect(pass, group % 4 * v.width + bounds[0], group / 4 * v.height + bounds[1],
                                      bounds[2], bounds[3]);
    fragment.f("u_visibility_group", (float)group);
    wgpuRenderPassEncoderSetViewport(pass, (float)(group % 4 * v.width), (float)(group / 4 * v.height), (float)v.width,
                                     (float)v.height, 0, 1);
    bind(ground_beam_vis, group_inputs, &vertex, &fragment);
    wgpuRenderPassEncoderDraw(pass, 4, 1, 0, 0);
  }
  end_pass();
}

// Full-resolution material shading samples one coarse RGBA group per four
// lights. No body-grid texture or shadow walk is bound to this program.
bool ground_draw(const Geometry &geometry) {
  auto it = textures.find(bound[0]);
  if (!bound[0] || it == textures.end() || !(it->second.flags & TARGET_RENDER))
    return false;
  Ground &g = ground_of(bound[0]);
  Target &t = drawing_target(current_target);
  if (visibility_dirty)
    prepare_ground_visibility(t.logical_width, t.logical_height);
  pass_into(t);
  Uniforms vertex(*ground_lit.vert), fragment(*ground_lit.frag);
  vertex.v2("target_size", (float)t.logical_width, (float)t.logical_height).v2("camera", scene_camera[0], scene_camera[1]);
  fragment.set("u_ground_size", ground_size, 8).f("u_time_s", scene_seconds - g.epoch).i("u_debug", scene_debug < DEBUG_SMOKE ? scene_debug : 0);
  fragment.i("u_debug_display", 1);
  fragment.i("u_spec_light_count", light_count).i("u_has_beam_lights", beam_lights).set("u_beam_gain", beam_gain, 8);
  fragment.set("u_visibility_world", ground_visibility.rect, 16);
  fragment.v2("u_visibility_size", (float)std::max(1, ground_visibility.width), (float)std::max(1, ground_visibility.height));
  fragment.set("u_spec_pos", light_pos, light_count * 16).set("u_spec_color", light_rgb, light_count * 16);
  fragment.set("u_spec_dir", ground_dir, light_count * 16).set("u_spec_response", light_response, light_count * 16);
  fragment.set("u_spec_tail", light_tail, (light_count + 3) / 4 * 16).set("u_beam_shape", beam_shape, light_count * 16);
  WGPUBindGroup group = fragment_group(ground_lit, {{"u_substrate_tex", g.substrate.view, linear_clamp()},
                                                    {"u_surface_tex", g.surface.view, linear_clamp()},
                                                    {"u_material_tex", g.coverage.view, linear_clamp()},
                                                    {"u_visibility_tex", ground_visibility.count ? beam_vis.view : blank_view,
                                                     linear_clamp()}});
  Output o = device_output(t, geometry.topology);
  o.blend = false; // the ground is opaque
  wgpuRenderPassEncoderSetPipeline(pass, pipeline(ground_lit, o));
  bind(ground_lit, group, &vertex, &fragment);
  draw_geometry(geometry);
  return true;
}

// --- RTX fluid smoke (game/rtx_smoke.cpp), as in renderer.cpp ---------------------
enum { SMOKE_TARGETS = 5, SMOKE_DISPLAY_MAX_AXIS = 640 };
Target smoke_targets[SMOKE_TARGETS], smoke_composite;
int smoke_current, smoke_iterations;
float smoke_resolution, smoke_world[2], smoke_dt, smoke_decay = 0.2f, smoke_fade = 1;

void release_smoke() {
  for (Target &t : smoke_targets)
    release(t);
  release(smoke_composite);
}

// A rect of a smoke target through one of the solver's programs, with `o`'s blend.
void smoke_rect(Program &p, Target &into, const float *rect, Uniforms &fragment, Output o,
                std::initializer_list<Input> inputs) {
  pass_into(into);
  o.format = format_of(into);
  Uniforms vertex(*p.vert);
  vertex.set("rect", rect, 16);
  fragment.v2("u_resolution", smoke_resolution, smoke_resolution).set("u_world_size", smoke_world, 8);
  wgpuRenderPassEncoderSetPipeline(pass, pipeline(p, o));
  bind(p, fragment_group(p, inputs), &vertex, &fragment);
  wgpuRenderPassEncoderDraw(pass, 4, 1, 0, 0);
}

void smoke_pass(int destination, int source, int mode, int aux = -1) {
  if (!fits(uniform_stream, 4096))
    submit();
  Uniforms fragment(*smoke_solver.frag);
  fragment.i("u_mode", mode).f("u_dt", smoke_dt).f("u_decay", smoke_decay).f("u_fade", smoke_fade);
  const float whole[4] = {0, 0, 1, 1};
  smoke_rect(smoke_solver, smoke_targets[destination], whole, fragment, Output{},
             {{"texture0", smoke_targets[source].view, linear_clamp()},
              {"u_aux", aux >= 0 ? smoke_targets[aux].view : blank_view, linear_clamp()}});
}

// Splats and impulses add into the state: its alpha is signed velocity, so ONE/ONE.
Output smoke_adding() {
  Output o;
  o.blend = true, o.src = o.dst = WGPUBlendFactor_One;
  return o;
}

bool wgpu_renderer_set_rtx(bool enabled) {
  rtx = enabled;
  world = false;
  visibility_dirty = true;
  ground_visibility = {};
  release(hdr);
  // Classic bakes leave the ground's companions behind: RTX makes them afresh.
  while (!grounds.empty())
    drop_ground(grounds.begin()->first);
  release_smoke();
  release(heat_trail);
  release(beam_vis);
  heat_seconds = -1;
  release(pressured);
  release(discarded);
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
// WebGPU's timestamp queries need a device feature the page does not ask for.
void wgpu_renderer_frame_end() {}
bool wgpu_renderer_profile_frame(long long &, std::string &, bool &) { return false; }
bool wgpu_renderer_profile_gpu(long long &, std::string &) { return false; }

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
// Reading a target back waits on the GPU in WebGPU: a replay keeps no copies on disk there.
u32 wgpu_w2c_host_texture_read(struct w2c_host *, u32, u32, u32) { return 0; }
u32 wgpu_w2c_host_texture_write(struct w2c_host *, u32, u32, u32, u32) { return 0; }
void wgpu_w2c_host_texture_copy(struct w2c_host *, u32 destination, u32 source) {
  Target &from = target_or_back((int)source);
  if (!from.texture)
    return;
  drop_ground((int)destination);
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
  drop_ground((int)id);
  release(it->second);
  textures.erase(it);
  texel_addresses.erase((int)id);
  for (auto *maps : {&thickness_maps, &heat_density_maps}) {
    auto map = maps->find((int)id);
    if (map != maps->end()) {
      wgpuTextureViewRelease(map->second.view);
      wgpuTextureRelease(map->second.texture);
      maps->erase(map);
      forget_groups();
    }
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
  drop_ground(current_target);
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
  Geometry geometry;
  geometry.topology = primitive < 7 ? topologies[primitive] : WGPUPrimitiveTopology_TriangleList;
  geometry.vertex_bytes = (uint64_t)vertex_count * 28;
  geometry.index_bytes = index_data ? (uint64_t)index_count * 2 : 0;
  geometry.index_count = index_count;
  // Room for the draw and what a marked decal adds: its substrate, stamps, and the companions' first passes.
  uint64_t uniforms = 8 * (ground_lit.frag->uniform_size + ground_lit.vert->uniform_size + 512);
  // A late scene or body grid rebuilds the atlas in the ground's draw, after its geometry is in the streams.
  if (rtx && world && material == HOST_PASS_GROUND && visibility_dirty)
    uniforms += visibility_uniforms(MAX_LIGHTS / 4);
  if (!fits(vertex_stream, geometry.vertex_bytes + (uint64_t)vertex_count * 8) || !fits(index_stream, geometry.index_bytes + 3) ||
      !fits(uniform_stream, uniforms))
    submit();

  Target &t = drawing_target(current_target);
  // A marked decal reaches the ground's companions too: the substrate unless it
  // is blood, the materials if it has one. They start from the terrain before it.
  bool marked = rtx && ground_kind != HOST_GROUND_END && current_target && (t.flags & TARGET_RENDER);
  Ground *g = marked ? &ground_of(current_target) : nullptr;
  geometry.vertex_at = put(vertex_stream, client_memory() + vertices, geometry.vertex_bytes);
  if (index_data)
    geometry.index_at = put(index_stream, index_data, geometry.index_bytes);
  if (rtx && world && material == HOST_PASS_GROUND && ground_draw(geometry))
    return;

  pass_into(t);
  bool lit = rtx && world && material && material != HOST_PASS_GLINT && material != HOST_PASS_GROUND && (material != HOST_PASS_PLAYERS || light_count);
  Program &program = !lit                           ? classic
                     : material == HOST_PASS_PLAYERS ? player_lit
                     : material == MATERIAL_BONUS    ? bonus_lit
                     : material == HOST_PASS_HEAT    ? heat_body
                     : material == HOST_PASS_GLOW    ? contact_glow
                                                     : creature_lit;
  WGPUBindGroup vertex_textures = nullptr;
  if (lit && &program == &creature_lit) {
    std::vector<float> centers((size_t)vertex_count * 2);
    quad_centers((const float *)(client_memory() + vertices), vertex_count, centers.data());
    geometry.center_bytes = centers.size() * sizeof(float);
    geometry.center_at = put(vertex_stream, centers.data(), geometry.center_bytes);
    vertex_textures =
        vertex_group(program, {{"u_occlusion_tex", occlusion_grid[2] ? occlusion_view : blank_view, nearest_clamp()}});
  }
  if (lit) {
    Uniforms vertex(*program.vert), fragment(*program.frag);
    vertex.v2("target_size", (float)t.logical_width, (float)t.logical_height).v2("camera", scene_camera[0], scene_camera[1]);
    // creature_lit.vert's visibility at the corners (creature_visibility.glsl).
    vertex.i("u_count", light_count).set("u_occlusion_grid", occlusion_grid, 16).f("u_occlusion_cell_size", occlusion_cell);
    vertex.i("u_dynamic_shadows", dynamic_shadows).set("u_pos", light_pos, light_count * 16);
    vertex.set("u_rgb", light_rgb, light_count * 16).set("u_dir", light_dir, light_count * 16);
    vertex.set("u_response", light_response, light_count * 16);
    fragment.v4("colDiffuse", 1, 1, 1, 1).i("u_count", light_count).f("u_ambient", 0.6f);
    fragment.set("u_occlusion_grid", occlusion_grid, 16).f("u_occlusion_cell_size", occlusion_cell);
    fragment.i("u_dynamic_shadows", dynamic_shadows);
    fragment.i("u_pass", bonus_emblem).set("u_grid", bonus_grid, 8).set("u_shell_center", bonus_center, 8);
    int ice = material == HOST_PASS_ICE_CUBES || material == HOST_PASS_ICE_FROZEN ? 4 : material == HOST_PASS_ICE_SHARDS ? 8 : 0;
    fragment.i("u_ice", ice).i("u_ice_frozen", material == HOST_PASS_ICE_FROZEN);
    fragment.set("u_pos", light_pos, light_count * 16).set("u_rgb", light_rgb, light_count * 16);
    fragment.set("u_dir", light_dir, light_count * 16).set("u_response", light_response, light_count * 16);
    auto it = textures.find(bound[0]);
    bool present = bound[0] && it != textures.end() && it->second.texture;
    WGPUSampler atlas_sampler = sampler(stage_states[0][TSS_ADDRESSU], stage_states[0][TSS_ADDRESSV],
                                        stage_states[0][TSS_MAGFILTER] >= 2, stage_states[0][TSS_MINFILTER] >= 2);
    WGPUTextureView shape = ice                               ? ice_view
                           : !present                        ? blank_view
                           : material == HOST_PASS_CREATURES ? shape_map(bound[0])
                           : material == HOST_PASS_HEAT      ? shape_map(bound[0], true)
                                                            : blank_view;
    wgpuRenderPassEncoderSetPipeline(pass, pipeline(program, device_output(t, geometry.topology)));
    bind(program,
         fragment_group(program, {{"texture0", present ? it->second.view : blank_view, atlas_sampler},
                                  {material == HOST_PASS_HEAT ? "u_density" : "u_thickness", shape, linear_clamp()},
                                  {"u_occlusion_tex", occlusion_grid[2] ? occlusion_view : blank_view, nearest_clamp()}}),
         &vertex, &fragment, vertex_textures);
  } else {
    bind_classic(t, geometry.topology);
  }
  draw_geometry(geometry);
  if (!g)
    return;
  if (ground_kind != HOST_GROUND_BLOOD) {
    pass_into(g->substrate);
    bind_classic(g->substrate, geometry.topology);
    draw_geometry(geometry);
  }
  if (ground_kind != HOST_GROUND_DECAL)
    stamp_ground(*g, ground_kind, geometry);
}
void wgpu_w2c_host_circle(struct w2c_host *, u32 shape, u32 color) {
  EffectVertex vertices[4];
  circle_quad((const float *)(client_memory() + shape), color, vertices, circle);
  // A strip of the fan's corners.
  std::swap(vertices[2], vertices[3]);
  Geometry geometry;
  geometry.topology = WGPUPrimitiveTopology_TriangleStrip;
  geometry.vertex_bytes = sizeof(vertices);
  geometry.index_count = 4;
  if (!fits(vertex_stream, geometry.vertex_bytes) || !fits(uniform_stream, 2 * (classic.frag->uniform_size + 512)))
    submit();
  geometry.vertex_at = put(vertex_stream, vertices, geometry.vertex_bytes);
  Target &t = drawing_target(current_target);
  pass_into(t);
  bind_classic(t, geometry.topology);
  draw_geometry(geometry);
  memset(circle, 0, sizeof(circle));
}
static void upload_analytic_vertices(const void *vertices, uint64_t bytes,
                                     int count) {
  uint64_t at = put(vertex_stream, vertices, bytes);
  wgpuRenderPassEncoderSetVertexBuffer(pass, 0, vertex_stream.buffer, at,
                                       bytes);
  wgpuRenderPassEncoderDraw(pass, count, 1, 0, 0);
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
  fragment.v4("colDiffuse", 1, 1, 1, 1).i("u_in_world", in_world(t));
  wgpuRenderPassEncoderSetPipeline(pass, pipeline(beam, device_output(t, WGPUPrimitiveTopology_TriangleStrip)));
  bind(beam, fragment_group(beam, {}), &vertex, &fragment);
  // The quad's corners run around it; a strip takes them as 0, 1, 3, 2.
  const float *c = (const float *)(client_memory() + corners);
  static const int order[4] = {0, 1, 3, 2};
  float strip[16];
  for (int i = 0; i < 4; ++i)
    memcpy(strip + i * 4, c + order[i] * 4, 16);
  upload_analytic_vertices(strip, sizeof strip, 4);
}
static void draw_effect_vertices(const EffectVertex *vertices, int count,
                                 int kind, const float *params) {
  uint64_t bytes = count * sizeof(EffectVertex);
  if (!fits(vertex_stream, bytes) || !fits(uniform_stream, 1024))
    submit();
  Target &t = drawing_target(current_target);
  pass_into(t);
  Uniforms vertex(*effect.vert), fragment(*effect.frag);
  vertex.v2("target_size", (float)t.logical_width, (float)t.logical_height);
  fragment.v4("colDiffuse", 1, 1, 1, 1)
      .i("u_kind", kind)
      .set("u_params", params, 48)
      .i("u_in_world", in_world(t));
  wgpuRenderPassEncoderSetPipeline(
      pass,
      pipeline(effect, device_output(t, WGPUPrimitiveTopology_TriangleList)));
  bind(effect, fragment_group(effect, {}), &vertex, &fragment);
  upload_analytic_vertices(vertices, bytes, count);
}
void wgpu_w2c_host_effect(struct w2c_host *, u32 corners, u32 kind, u32 params,
                          u32 color) {
  if (!rtx)
    return;
  EffectVertex vertices[6];
  effect_quad((const float *)(client_memory() + corners), color, vertices);
  draw_effect_vertices(vertices, 6, kind,
                       (const float *)(client_memory() + params));
}
void wgpu_w2c_host_effect_sprites(struct w2c_host *, u32 vertices, u32 kind,
                                  u32 count) {
  if (!rtx)
    return;
  const float params[12] = {};
  draw_effect_vertices((const EffectVertex *)(client_memory() + vertices),
                       count, kind, params);
}
void wgpu_w2c_host_scene(struct w2c_host *, u32 view, u32 lights, u32 count) {
  visibility_dirty = true;
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
  }
}
void wgpu_w2c_host_pressure(struct w2c_host *, u32 fronts, u32 count) {
  const float *f = (const float *)(client_memory() + fronts);
  pressure_fronts.assign(f, f + count * 4);
}
// Monster Vision's trail buffer (host_heat, host_heat_trails), as in renderer.cpp.
void wgpu_w2c_host_heat(struct w2c_host *, u32 footprints, u32 count) {
  if (!rtx || (!count && !heat_trail.texture))
    return;
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
  auto quad = [](std::vector<HostVertex> &v, float x0, float y0, float x1, float y1, u32 color) {
    auto corner = [&](float x, float y, float u, float w) { return HostVertex{x, y, 0, 1, color, u, w}; };
    for (HostVertex c : {corner(x0, y0, 0, 0), corner(x0, y1, 0, 1), corner(x1, y1, 1, 1), corner(x0, y0, 0, 0),
                         corner(x1, y1, 1, 1), corner(x1, y0, 1, 0)})
      v.push_back(c);
  };
  std::vector<HostVertex> whole, stamps;
  quad(whole, 0, 0, (float)width, (float)height, 0xffffffff);
  const float *f = (const float *)(client_memory() + footprints);
  for (u32 i = 0; i < count; ++i, f += 4) {
    float x = f[0] * HEAT_TRAIL_SCALE, y = f[1] * HEAT_TRAIL_SCALE, r = f[2] * HEAT_TRAIL_SCALE;
    quad(stamps, x - r, y - r, x + r, y + r, (u32)(std::min(1.0f, f[3]) * 255 + 0.5f) << 24 | 0xffffff);
  }
  uint64_t bytes = (whole.size() + stamps.size()) * sizeof(HostVertex);
  if (!fits(vertex_stream, bytes) || !fits(uniform_stream, 4 * 512))
    submit();
  bool fresh = gap < 0 || gap > HEAT_MAX_GAP_S;
  WGPUColor none = {0, 0, 0, 0};
  begin_pass(heat_trail, fresh ? &none : nullptr);
  Uniforms vertex(*heat_stamp.vert), fragment(*heat_stamp.frag);
  vertex.v2("target_size", (float)width, (float)height).v2("camera", 0, 0);
  WGPUBindGroup group = fragment_group(heat_stamp, {});
  auto draw = [&](const std::vector<HostVertex> &v, const Output &o, float fade) {
    fragment.f("u_fade", fade);
    wgpuRenderPassEncoderSetPipeline(pass, pipeline(heat_stamp, o));
    bind(heat_stamp, group, &vertex, &fragment);
    uint64_t at = put(vertex_stream, v.data(), v.size() * sizeof(HostVertex));
    wgpuRenderPassEncoderSetVertexBuffer(pass, 0, vertex_stream.buffer, at, v.size() * sizeof(HostVertex));
    wgpuRenderPassEncoderDraw(pass, (uint32_t)v.size(), 1, 0, 0);
  };
  Output o;
  o.format = format_of(heat_trail);
  o.topology = WGPUPrimitiveTopology_TriangleList;
  o.blend = true;
  if (!fresh && gap > 0) {
    o.src = WGPUBlendFactor_Zero, o.dst = WGPUBlendFactor_OneMinusSrcAlpha;
    draw(whole, o, 1 - powf(0.5f, gap / HEAT_HALF_LIFE_S));
  }
  if (!stamps.empty()) {
    // Maximum ignores the factors, which WebGPU then wants as one.
    o.src = o.dst = WGPUBlendFactor_One, o.op = WGPUBlendOperation_Max;
    draw(stamps, o, -1);
  }
  end_pass();
}
void wgpu_w2c_host_heat_trails(struct w2c_host *, f32 alpha) {
  if (!rtx || !world || !heat_trail.texture)
    return;
  if (!fits(vertex_stream, 6 * sizeof(HostVertex)) || !fits(uniform_stream, 2 * 512))
    submit();
  Target &t = drawing_target(current_target);
  pass_into(t);
  float w = (float)t.logical_width, h = (float)t.logical_height;
  const HostVertex quad[] = {{0, 0, 0, 1, 0xffffffff, 0, 0}, {0, h, 0, 1, 0xffffffff, 0, 0}, {w, h, 0, 1, 0xffffffff, 0, 0},
                             {0, 0, 0, 1, 0xffffffff, 0, 0}, {w, h, 0, 1, 0xffffffff, 0, 0}, {w, 0, 0, 1, 0xffffffff, 0, 0}};
  Uniforms vertex(*heat_trail_program.vert), fragment(*heat_trail_program.frag);
  vertex.v2("target_size", w, h).v2("camera", scene_camera[0], scene_camera[1]);
  fragment.set("u_ground_size", ground_size, 8).f("u_alpha", alpha);
  Output o;
  o.format = format_of(t);
  o.topology = WGPUPrimitiveTopology_TriangleList;
  o.blend = true, o.src = o.dst = WGPUBlendFactor_One;
  wgpuRenderPassEncoderSetPipeline(pass, pipeline(heat_trail_program, o));
  bind(heat_trail_program, fragment_group(heat_trail_program, {{"u_heat", heat_trail.view, linear_clamp()}}), &vertex,
       &fragment);
  uint64_t at = put(vertex_stream, quad, sizeof quad);
  wgpuRenderPassEncoderSetVertexBuffer(pass, 0, vertex_stream.buffer, at, sizeof quad);
  wgpuRenderPassEncoderDraw(pass, 6, 1, 0, 0);
}
void wgpu_w2c_host_ground(struct w2c_host *, u32 kind, f32 seconds) {
  ground_kind = (int)kind;
  ground_seconds = seconds;
}
void wgpu_w2c_host_smoke(struct w2c_host *, u32 commands, u32 count) {
  if (!rtx)
    return;
  const float *c = (const float *)(client_memory() + commands), *end = c + count;
  while (c < end) {
    switch ((int)*c) {
    case SMOKE_RESET: {
      smoke_resolution = c[1], smoke_world[0] = c[2], smoke_world[1] = c[3], smoke_dt = c[4];
      smoke_iterations = (int)c[5];
      WGPUColor none = {0, 0, 0, 0};
      for (Target &t : smoke_targets) {
        if (t.width != (int)smoke_resolution) {
          release(t);
          t.width = t.height = t.logical_width = t.logical_height = (int)smoke_resolution;
          t.flags = TARGET_RENDER | TARGET_HALF_FLOAT;
          allocate(t);
        }
        begin_pass(t, &none);
      }
      smoke_current = 0;
      c += 6;
      break;
    }
    case SMOKE_FADE:
      smoke_fade = c[1];
      smoke_pass(1 - smoke_current, smoke_current, 5);
      smoke_current = 1 - smoke_current;
      c += 2;
      break;
    case SMOKE_SPLAT: {
      if (!fits(uniform_stream, 2048))
        submit();
      Uniforms fragment(*smoke_splat.frag);
      fragment.set("u_source", c + 5, 16).set("u_motion", c + 9, 16).f("u_rotation", c[13]).set("u_flow", c + 14, 16);
      smoke_rect(smoke_splat, smoke_targets[smoke_current], c + 1, fragment, smoke_adding(), {});
      c += 18;
      break;
    }
    case SMOKE_IMPULSE: {
      if (!fits(uniform_stream, 2048))
        submit();
      Uniforms fragment(*smoke_impulse.frag);
      fragment.set("u_segment", c + 5, 16).set("u_impulse", c + 9, 16).set("u_phase", c + 13, 16);
      smoke_rect(smoke_impulse, smoke_targets[smoke_current], c + 1, fragment, smoke_adding(), {});
      c += 17;
      break;
    }
    case SMOKE_PROJECT: {
      // Advect velocity, take its divergence, relax pressure, then subtract its gradient.
      int other = 1 - smoke_current;
      smoke_pass(other, smoke_current, 0);
      smoke_pass(2, other, 1);
      WGPUColor none = {0, 0, 0, 0};
      begin_pass(smoke_targets[3], &none);
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
      float paths[64 * 4], motions[64 * 4];
      for (int i = 0; i < count; ++i) {
        memcpy(paths + i * 4, c + 2 + i * 8, 16);
        memcpy(motions + i * 4, c + 6 + i * 8, 16);
      }
      if (!fits(uniform_stream, 4096))
        submit();
      Uniforms fragment(*smoke_solver.frag);
      fragment.i("u_mode", 6).f("u_dt", smoke_dt).i("u_body_count", count);
      fragment.set("u_body_path", paths, count * 16).set("u_body_motion", motions, count * 16);
      const float whole[4] = {0, 0, 1, 1};
      smoke_rect(smoke_solver, smoke_targets[1 - smoke_current], whole, fragment, Output{},
                 {{"texture0", smoke_targets[smoke_current].view, linear_clamp()}, {"u_aux", blank_view, linear_clamp()}});
      smoke_current = 1 - smoke_current;
      c += 2 + (int)c[1] * 8;
      break;
    }
    default:
      client_fatal("Unknown smoke command");
    }
  }
}
void wgpu_w2c_host_smoke_draw(struct w2c_host *, u32 view, u32 lights, u32 light_count, u32 sights,
                              u32 sight_count) {
  if (!rtx || !world || !smoke_targets[0].texture)
    return;
  if (!fits(uniform_stream, 4096))
    submit();
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
  WGPUColor none = {0, 0, 0, 0};
  begin_pass(smoke_composite, &none);
  // Straight RGB becomes premultiplied once; alpha accumulates as alpha.
  Output o;
  o.format = format_of(smoke_composite);
  o.blend = true, o.src = WGPUBlendFactor_SrcAlpha, o.dst = WGPUBlendFactor_OneMinusSrcAlpha;
  o.alpha_src = WGPUBlendFactor_One, o.alpha_dst = WGPUBlendFactor_OneMinusSrcAlpha;
  Uniforms vertex(*smoke_display.vert), fragment(*smoke_display.frag);
  vertex.set("rect", v, 16).v2("target_size", (float)t.logical_width, (float)t.logical_height);
  fragment.i("u_state_flip", 1).set("u_origin", v + 4, 8).set("u_size", v + 6, 8).f("u_opacity", v[8]).i("u_debug", scene_debug >= DEBUG_SMOKE ? scene_debug : 0);
  fragment.i("u_light_count", (int)light_count).i("u_sight_count", (int)sight_count);
  float pos[SMOKE_MAX_LIGHTS * 4], rgb[SMOKE_MAX_LIGHTS * 4], shape[SMOKE_MAX_LIGHTS * 4], tails[SMOKE_MAX_LIGHTS] = {};
  const float *l = (const float *)(client_memory() + lights);
  for (u32 i = 0; i < light_count && i < SMOKE_MAX_LIGHTS; ++i, l += SMOKE_LIGHT_FLOATS) {
    memcpy(pos + i * 4, l, 16);
    memcpy(rgb + i * 4, l + 4, 16);
    memcpy(shape + i * 4, l + 8, 16);
    tails[i] = l[12];
  }
  fragment.set("u_light_pos", pos, light_count * 16).set("u_light_rgb", rgb, light_count * 16);
  fragment.set("u_light_shape", shape, light_count * 16).set("u_light_tail", tails, (light_count + 3) / 4 * 16);
  fragment.set("u_sights", client_memory() + sights, sight_count * 16);
  wgpuRenderPassEncoderSetPipeline(pass, pipeline(smoke_display, o));
  bind(smoke_display,
       fragment_group(smoke_display, {{"texture0", smoke_targets[smoke_current].view, linear_clamp()}}), &vertex,
       &fragment);
  wgpuRenderPassEncoderDraw(pass, 4, 1, 0, 0);
  // The premultiplied composite over the world.
  smoke_drawing = true;
  Target &into = drawing_target(current_target);
  smoke_drawing = false;
  pass_into(into);
  Output over;
  over.format = format_of(into);
  over.blend = true, over.src = WGPUBlendFactor_One, over.dst = WGPUBlendFactor_OneMinusSrcAlpha;
  over.mask = into.flags & TARGET_OPAQUE ? 7 : 15;
  wgpuRenderPassEncoderSetPipeline(pass, pipeline(blit, over));
  bind(blit, fragment_group(blit, {{"source", smoke_composite.view, linear_clamp()}}), nullptr, nullptr);
  wgpuRenderPassEncoderDraw(pass, 4, 1, 0, 0);
}
void wgpu_w2c_host_occlusion(struct w2c_host *, u32 grid, u32 values, u32 count) {
  visibility_dirty = true;
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
  if (pass_kind == HOST_PASS_WORLD_BEGIN) { // Scene/occlusion inputs have arrived; shade masks before HDR.
    prepare_ground_visibility(back.logical_width, back.logical_height);
    int width = back.width, height = back.height;
    world_size(back.logical_width, width, height);
    if (hdr.width != width || hdr.height != height || !hdr.texture) {
      release(hdr);
      hdr.width = width;
      hdr.height = height;
      hdr.flags = back.flags | TARGET_HALF_FLOAT;
      allocate(hdr);
    }
    hdr.logical_width = back.logical_width;
    hdr.logical_height = back.logical_height;
    if (debug_map() && (discarded.width != width || discarded.height != height || !discarded.texture)) {
      release(discarded);
      discarded.width = width, discarded.height = height, discarded.flags = hdr.flags;
      allocate(discarded);
    }
    discarded.logical_width = hdr.logical_width, discarded.logical_height = hdr.logical_height;
    if (scene_debug >= DEBUG_SMOKE) { // the smoke's maps over black
      WGPUColor black = {0, 0, 0, 1};
      begin_pass(hdr, &black);
    } else {
      copy(back, hdr);
    }
    world = true;
  } else if (pass_kind == HOST_PASS_WORLD_END && world) {
    world = false;
    material = 0;
    if (!fits(uniform_stream, 2048))
      submit();
    // The pressure fronts displace the world, in its own pixels, into a second target.
    Target *world_image = &hdr;
    if (!pressure_fronts.empty()) {
      if (pressured.width != hdr.width || pressured.height != hdr.height) {
        release(pressured);
        pressured.width = hdr.width, pressured.height = hdr.height, pressured.flags = hdr.flags;
        allocate(pressured);
      }
      float sx = (float)hdr.width / hdr.logical_width, sy = (float)hdr.height / hdr.logical_height;
      int count = std::min((int)pressure_fronts.size() / 4, 16);
      float fronts[16 * 4] = {}, strengths[16] = {};
      for (int i = 0; i < count; ++i) {
        const float *f = &pressure_fronts[i * 4];
        const float front[4] = {f[0] * sx, f[1] * sy, f[2] * sx, f[2] * sy};
        memcpy(fronts + i * 4, front, sizeof front);
        strengths[i] = f[3];
      }
      begin_pass(pressured, nullptr);
      Output po;
      po.format = format_of(pressured);
      po.mask = pressured.flags & TARGET_OPAQUE ? 7 : 15;
      Uniforms pf(*pressure_fronts_program.frag);
      pf.v2("u_size", (float)hdr.width, (float)hdr.height).i("u_count", count);
      pf.set("u_fronts", fronts, count * 16).set("u_strength", strengths, (count + 3) / 4 * 16);
      wgpuRenderPassEncoderSetPipeline(pass, pipeline(pressure_fronts_program, po));
      bind(pressure_fronts_program, fragment_group(pressure_fronts_program, {{"texture0", hdr.view, linear_clamp()}}),
           nullptr, &pf);
      wgpuRenderPassEncoderDraw(pass, 4, 1, 0, 0);
      world_image = &pressured;
    }
    begin_pass(back, nullptr);
    Output o;
    o.format = format_of(back);
    o.mask = 7;
    // A world drawn smaller (render_size) scales up as it tonemaps; a debug
    // map's values go to the display as they are.
    bool exact = world_image->width == back.width && world_image->height == back.height;
    if (debug_map()) {
      wgpuRenderPassEncoderSetPipeline(pass, pipeline(blit, o));
      bind(blit, fragment_group(blit, {{"source", world_image->view, exact ? nearest_clamp() : linear_clamp()}}),
           nullptr, nullptr);
      wgpuRenderPassEncoderDraw(pass, 4, 1, 0, 0);
      end_pass();
      return;
    }
    Uniforms fragment(*tonemap.frag);
    fragment.v4("colDiffuse", 1, 1, 1, 1).f("u_edr_headroom", edr_headroom);
    wgpuRenderPassEncoderSetPipeline(pass, pipeline(tonemap, o));
    bind(tonemap, fragment_group(tonemap, {{"texture0", world_image->view, exact ? nearest_clamp() : linear_clamp()}}),
         nullptr, &fragment);
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
