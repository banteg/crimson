// The Win32 and DirectX 8 surface below the recovered Grim: a Direct3D device
// that hands its draws to the host, DirectInput devices that read the state the
// host last delivered, and the few Win32 calls Grim makes. Any interface method
// not implemented here stops the module with its name (com_defaults.h).
#include "com_defaults.h"
#include "grim2d_cpp.h"
#include "host_abi.h"
#include <mmsystem.h>
#include <new>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void platform_unimplemented(const char *method) {
  static char message[160];
  snprintf(message, sizeof(message), "unimplemented platform call %s", method);
  host_fatal(message);
}
[[noreturn]] static void platform_fail(const char *what) { host_fatal(what); }

// Headless, the game draws into nothing: no host call is made.
static bool outputs;
extern "C" __attribute__((export_name("game_outputs"))) void game_outputs(int enabled) { outputs = enabled != 0; }

// --- Direct3D 8 ---------------------------------------------------------------

static int texture_ids;

struct Texture;
struct Surface final : UnimplementedIDirect3DSurface8 {
  ULONG refs = 1;
  Texture *owner = nullptr; // a texture's level, else the back buffer or an image surface
  UINT width = 0, height = 0;
  D3DFORMAT format = D3DFMT_A8R8G8B8;
  unsigned char *texels = nullptr; // image surfaces only
  STDMETHOD_(ULONG, AddRef)(THIS) override;
  STDMETHOD_(ULONG, Release)(THIS) override;
  STDMETHOD(GetDesc)(THIS_ D3DSURFACE_DESC *desc) override {
    memset(desc, 0, sizeof(*desc));
    desc->Format = format;
    desc->Type = D3DRTYPE_SURFACE;
    desc->Width = width;
    desc->Height = height;
    desc->Size = width * height * 4;
    return D3D_OK;
  }
  STDMETHOD(LockRect)(THIS_ D3DLOCKED_RECT *locked, const RECT *rect, DWORD) override;
  STDMETHOD(UnlockRect)(THIS) override;
};

struct Texture final : UnimplementedIDirect3DTexture8 {
  ULONG refs = 1;
  int id = 0;
  UINT width = 0, height = 0;
  DWORD usage = 0;
  D3DFORMAT format = D3DFMT_A8R8G8B8;
  unsigned char *texels = nullptr;
  Surface level;
  Texture(UINT w, UINT h, DWORD u, D3DFORMAT f) : id(++texture_ids), width(w), height(h), usage(u), format(f) {
    texels = (unsigned char *)calloc(width * height, 4);
    level.owner = this;
    level.width = width;
    level.height = height;
    level.format = format;
    if (outputs)
      host_texture_create(id, width, height,
                          ((usage & D3DUSAGE_RENDERTARGET) ? 1 : 0) | (format == D3DFMT_X8R8G8B8 ? 2 : 0));
  }
  STDMETHOD_(ULONG, AddRef)(THIS) override { return ++refs; }
  STDMETHOD_(ULONG, Release)(THIS) override {
    if (--refs)
      return refs;
    if (outputs)
      host_texture_release(id);
    free(texels);
    delete this;
    return 0;
  }
  STDMETHOD_(DWORD, GetLevelCount)(THIS) override { return 1; }
  STDMETHOD(GetLevelDesc)(THIS_ UINT index, D3DSURFACE_DESC *desc) override {
    if (index)
      return D3DERR_INVALIDCALL;
    level.GetDesc(desc);
    desc->Usage = usage;
    desc->Pool = D3DPOOL_MANAGED;
    return D3D_OK;
  }
  STDMETHOD(GetSurfaceLevel)(THIS_ UINT index, IDirect3DSurface8 **surface) override {
    if (index)
      return D3DERR_INVALIDCALL;
    AddRef();
    *surface = &level;
    return D3D_OK;
  }
  STDMETHOD(LockRect)(THIS_ UINT index, D3DLOCKED_RECT *locked, const RECT *rect, DWORD) override {
    if (index)
      return D3DERR_INVALIDCALL;
    locked->Pitch = width * 4;
    locked->pBits = texels + (rect ? rect->top * locked->Pitch + rect->left * 4 : 0);
    return D3D_OK;
  }
  STDMETHOD(UnlockRect)(THIS_ UINT index) override {
    if (index)
      return D3DERR_INVALIDCALL;
    if (format == D3DFMT_X8R8G8B8)
      for (UINT i = 0; i < width * height; ++i)
        texels[i * 4 + 3] = 0xff;
    if (outputs)
      host_texture_upload(id, texels);
    return D3D_OK;
  }
};

ULONG Surface::AddRef() { return owner ? owner->AddRef() : ++refs; }
ULONG Surface::Release() {
  if (owner)
    return owner->Release();
  if (--refs)
    return refs;
  free(texels);
  delete this;
  return 0;
}
HRESULT Surface::LockRect(D3DLOCKED_RECT *locked, const RECT *rect, DWORD flags) {
  if (owner)
    return owner->LockRect(0, locked, rect, flags);
  if (!texels)
    return D3DERR_INVALIDCALL; // the back buffer is the host's
  locked->Pitch = width * 4;
  locked->pBits = texels + (rect ? rect->top * locked->Pitch + rect->left * 4 : 0);
  return D3D_OK;
}
HRESULT Surface::UnlockRect() { return owner ? owner->UnlockRect(0) : D3D_OK; }

struct Buffer {
  ULONG refs = 1;
  unsigned char *bytes;
  explicit Buffer(UINT length) : bytes((unsigned char *)calloc(length, 1)) {}
};
struct VertexBuffer final : UnimplementedIDirect3DVertexBuffer8, Buffer {
  using Buffer::Buffer;
  STDMETHOD_(ULONG, AddRef)(THIS) override { return ++refs; }
  STDMETHOD_(ULONG, Release)(THIS) override {
    if (--refs)
      return refs;
    free(bytes);
    delete this;
    return 0;
  }
  STDMETHOD(Lock)(THIS_ UINT offset, UINT, BYTE **data, DWORD) override {
    *data = bytes + offset;
    return D3D_OK;
  }
  STDMETHOD(Unlock)(THIS) override { return D3D_OK; }
};
struct IndexBuffer final : UnimplementedIDirect3DIndexBuffer8, Buffer {
  using Buffer::Buffer;
  STDMETHOD_(ULONG, AddRef)(THIS) override { return ++refs; }
  STDMETHOD_(ULONG, Release)(THIS) override {
    if (--refs)
      return refs;
    free(bytes);
    delete this;
    return 0;
  }
  STDMETHOD(Lock)(THIS_ UINT offset, UINT, BYTE **data, DWORD) override {
    *data = bytes + offset;
    return D3D_OK;
  }
  STDMETHOD(Unlock)(THIS) override { return D3D_OK; }
};

// The flexible vertex format Grim draws with: XYZRHW, DIFFUSE and one TEX.
constexpr DWORD grim_fvf = D3DFVF_XYZRHW | D3DFVF_DIFFUSE | D3DFVF_TEX1;
constexpr UINT grim_stride = 28;

static int texture_id(IDirect3DBaseTexture8 *texture) {
  return texture ? static_cast<Texture *>(static_cast<IDirect3DTexture8 *>(texture))->id : 0;
}

struct Device final : UnimplementedIDirect3DDevice8 {
  ULONG refs = 1;
  UINT width, height;
  // The back buffer outlives the device while anyone still holds it.
  Surface *back_buffer = new Surface;
  Surface *target = back_buffer;
  VertexBuffer *stream = nullptr;
  IndexBuffer *indices = nullptr;
  UINT base_vertex = 0;
  DWORD render_states[256] = {};
  Device(UINT w, UINT h) : width(w), height(h) {
    back_buffer->width = w;
    back_buffer->height = h;
    back_buffer->refs = 2; // the device's own reference, and its binding as the target
  }
  STDMETHOD_(ULONG, AddRef)(THIS) override { return ++refs; }
  STDMETHOD_(ULONG, Release)(THIS) override {
    if (--refs)
      return refs;
    target->Release();
    back_buffer->Release();
    delete this;
    return 0;
  }
  STDMETHOD(TestCooperativeLevel)(THIS) override { return D3D_OK; }
  STDMETHOD(GetDeviceCaps)(THIS_ D3DCAPS8 *caps) override;
  STDMETHOD(Reset)(THIS_ D3DPRESENT_PARAMETERS *parameters) override {
    width = back_buffer->width = parameters->BackBufferWidth;
    height = back_buffer->height = parameters->BackBufferHeight;
    if (outputs)
      host_back_buffer(width, height);
    return D3D_OK;
  }
  STDMETHOD(Present)(THIS_ const RECT *, const RECT *, HWND, const RGNDATA *) override {
    if (outputs)
      host_present();
    return D3D_OK;
  }
  STDMETHOD_(void, SetGammaRamp)(THIS_ DWORD, const D3DGAMMARAMP *ramp) override {
    if (outputs)
      host_gamma_ramp(ramp->red, ramp->green, ramp->blue);
  }
  STDMETHOD(CreateTexture)(THIS_ UINT w, UINT h, UINT, DWORD usage, D3DFORMAT format, D3DPOOL,
                           IDirect3DTexture8 **texture) override {
    if (format != D3DFMT_A8R8G8B8 && format != D3DFMT_X8R8G8B8)
      return D3DERR_INVALIDCALL;
    *texture = new Texture(w, h, usage, format);
    return D3D_OK;
  }
  STDMETHOD(CreateVertexBuffer)(THIS_ UINT length, DWORD, DWORD, D3DPOOL, IDirect3DVertexBuffer8 **buffer) override {
    *buffer = new VertexBuffer(length);
    return D3D_OK;
  }
  STDMETHOD(CreateIndexBuffer)(THIS_ UINT length, DWORD, D3DFORMAT format, D3DPOOL,
                               IDirect3DIndexBuffer8 **buffer) override {
    if (format != D3DFMT_INDEX16)
      return D3DERR_INVALIDCALL;
    *buffer = new IndexBuffer(length);
    return D3D_OK;
  }
  STDMETHOD(CreateImageSurface)(THIS_ UINT w, UINT h, D3DFORMAT format, IDirect3DSurface8 **result) override {
    auto *surface = new Surface;
    surface->width = w;
    surface->height = h;
    surface->format = format;
    surface->texels = (unsigned char *)calloc(w * h, 4);
    *result = surface;
    return D3D_OK;
  }
  STDMETHOD(SetRenderTarget)(THIS_ IDirect3DSurface8 *surface, IDirect3DSurface8 *) override {
    // The device holds its render target, as Direct3D does.
    Surface *next = surface ? static_cast<Surface *>(surface) : back_buffer;
    next->AddRef();
    target->Release();
    target = next;
    if (outputs)
      host_set_render_target(target->owner ? target->owner->id : 0);
    return D3D_OK;
  }
  STDMETHOD(GetRenderTarget)(THIS_ IDirect3DSurface8 **surface) override {
    target->AddRef();
    *surface = target;
    return D3D_OK;
  }
  STDMETHOD(BeginScene)(THIS) override { return D3D_OK; }
  STDMETHOD(EndScene)(THIS) override { return D3D_OK; }
  STDMETHOD(Clear)(THIS_ DWORD, const D3DRECT *, DWORD, D3DCOLOR color, float, DWORD) override {
    if (outputs)
      host_clear(color);
    return D3D_OK;
  }
  STDMETHOD(SetRenderState)(THIS_ D3DRENDERSTATETYPE state, DWORD value) override {
    if ((unsigned)state < 256)
      render_states[state] = value;
    if (outputs)
      host_render_state(state, value);
    return D3D_OK;
  }
  STDMETHOD(GetRenderState)(THIS_ D3DRENDERSTATETYPE state, DWORD *value) override {
    *value = (unsigned)state < 256 ? render_states[state] : 0;
    return D3D_OK;
  }
  STDMETHOD(SetTexture)(THIS_ DWORD stage, IDirect3DBaseTexture8 *texture) override {
    if (outputs)
      host_set_texture(stage, texture_id(texture));
    return D3D_OK;
  }
  STDMETHOD(SetTextureStageState)(THIS_ DWORD stage, D3DTEXTURESTAGESTATETYPE state, DWORD value) override {
    if (outputs)
      host_texture_stage_state(stage, state, value);
    return D3D_OK;
  }
  STDMETHOD(SetVertexShader)(THIS_ DWORD fvf) override {
    if (fvf != grim_fvf)
      platform_fail("unsupported vertex format");
    return D3D_OK;
  }
  STDMETHOD(SetStreamSource)(THIS_ UINT number, IDirect3DVertexBuffer8 *buffer, UINT stride) override {
    if (number != 0 || stride != grim_stride)
      platform_fail("unsupported vertex stream");
    stream = static_cast<VertexBuffer *>(buffer);
    return D3D_OK;
  }
  STDMETHOD(SetIndices)(THIS_ IDirect3DIndexBuffer8 *buffer, UINT base) override {
    indices = static_cast<IndexBuffer *>(buffer);
    base_vertex = base;
    return D3D_OK;
  }
  STDMETHOD(DrawPrimitive)(THIS_ D3DPRIMITIVETYPE type, UINT start, UINT count) override {
    if (outputs)
      host_draw(type, stream->bytes + start * grim_stride, vertex_count(type, count), nullptr, count);
    return D3D_OK;
  }
  STDMETHOD(DrawIndexedPrimitive)(THIS_ D3DPRIMITIVETYPE type, UINT minimum, UINT count, UINT start,
                                  UINT primitives) override {
    if (outputs)
      host_draw(type, stream->bytes + base_vertex * grim_stride, minimum + count,
                (const unsigned short *)indices->bytes + start, primitives);
    return D3D_OK;
  }
  static int vertex_count(D3DPRIMITIVETYPE type, UINT primitives) {
    switch (type) {
    case D3DPT_POINTLIST:
      return primitives;
    case D3DPT_LINELIST:
      return primitives * 2;
    case D3DPT_LINESTRIP:
      return primitives + 1;
    case D3DPT_TRIANGLELIST:
      return primitives * 3;
    default:
      return primitives + 2;
    }
  }
};

static void device_caps(D3DCAPS8 *caps) {
  memset(caps, 0, sizeof(*caps));
  caps->DeviceType = D3DDEVTYPE_HAL;
  caps->MaxTextureWidth = 4096;
  caps->MaxTextureHeight = 4096;
  caps->MaxTextureAspectRatio = 4096;
  caps->MaxSimultaneousTextures = 2;
  caps->MaxTextureBlendStages = 2;
  caps->TextureCaps = D3DPTEXTURECAPS_ALPHA;
  caps->SrcBlendCaps = caps->DestBlendCaps = 0x1fff;
  caps->RasterCaps = D3DPRASTERCAPS_DITHER;
}
HRESULT Device::GetDeviceCaps(D3DCAPS8 *caps) {
  device_caps(caps);
  return D3D_OK;
}

struct Direct3D final : UnimplementedIDirect3D8 {
  STDMETHOD_(ULONG, AddRef)(THIS) override { return 1; }
  STDMETHOD_(ULONG, Release)(THIS) override { return 1; }
  STDMETHOD_(UINT, GetAdapterCount)(THIS) override { return 1; }
  STDMETHOD(GetAdapterIdentifier)(THIS_ UINT, DWORD, D3DADAPTER_IDENTIFIER8 *identifier) override {
    memset(identifier, 0, sizeof(*identifier));
    strcpy(identifier->Description, "Crimson host renderer");
    return D3D_OK;
  }
  STDMETHOD(GetAdapterDisplayMode)(THIS_ UINT, D3DDISPLAYMODE *mode) override {
    mode->Width = 1024;
    mode->Height = 768;
    mode->RefreshRate = 60;
    mode->Format = D3DFMT_X8R8G8B8;
    return D3D_OK;
  }
  STDMETHOD(CheckDeviceFormat)(THIS_ UINT, D3DDEVTYPE, D3DFORMAT, DWORD, D3DRESOURCETYPE, D3DFORMAT format) override {
    return format == D3DFMT_A8R8G8B8 || format == D3DFMT_X8R8G8B8 ? D3D_OK : D3DERR_NOTAVAILABLE;
  }
  STDMETHOD(GetDeviceCaps)(THIS_ UINT, D3DDEVTYPE, D3DCAPS8 *caps) override {
    device_caps(caps);
    return D3D_OK;
  }
  STDMETHOD(CreateDevice)(THIS_ UINT, D3DDEVTYPE, HWND, DWORD, D3DPRESENT_PARAMETERS *parameters,
                          struct IDirect3DDevice8 **device) override {
    *device = new Device(parameters->BackBufferWidth, parameters->BackBufferHeight);
    if (outputs)
      host_back_buffer(parameters->BackBufferWidth, parameters->BackBufferHeight);
    return D3D_OK;
  }
};
static Direct3D direct3d;

extern "C" {
IDirect3D8 *WINAPI Direct3DCreate8(UINT) { return &direct3d; }

// --- Win32 ----------------------------------------------------------------------

HMODULE WINAPI GetModuleHandleA(LPCSTR) { return nullptr; }
HWND WINAPI GetForegroundWindow(void) { return nullptr; }
HWND WINAPI GetDesktopWindow(void) { return nullptr; }
int WINAPI MessageBoxA(HWND, LPCSTR text, LPCSTR caption, UINT) {
  if (outputs)
    host_message(text, caption);
  return 0;
}
char *_getcwd(char *buffer, int size) {
  if (size > 0)
    buffer[0] = 0;
  return buffer;
}
DWORD WINAPI timeGetTime(void) { return host_time_ms(); }
UINT WINAPI timeBeginPeriod(UINT) { return 0; }
UINT WINAPI timeEndPeriod(UINT) { return 0; }
}

// Headless, the module owns a device that is never ready, so Grim's state calls
// land somewhere and its draws stop at grim_device_ready.
extern "C" IDirect3DDevice8 *grim_d3d_device;
void platform_headless_device() { grim_d3d_device = new Device(1024, 768); }

// --- Win32 left to the host ------------------------------------------------------

extern "C" {
int WINAPI GetKeyNameTextA(LONG, LPSTR text, int size) {
  if (size > 0)
    text[0] = 0;
  return 0;
}
int grim_run_loop(void) { platform_unimplemented("grim_run_loop"); }
double crt_atof_l(char *text) { return atof(text); }
}
// The host owns the window.
bool grim_window_create(void) { return true; }
BOOL grim_window_destroy(void) { return 1; }
bool IGrim2D_cpp::grim_apply_config(void) { return true; }
