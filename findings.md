# DirectX Header Analysis Findings

## Current Header Status

### What We Have (`third_party/headers/`)
- **DirectX**: `d3d8.h`, `d3d8caps.h`, `d3d8types.h`, `d3dtypes.h`, `dinput.h`, `dsound.h`
- **Multimedia**: `mmreg.h`, `mmsystem.h`
- **Codecs**: `jpeglib.h`, `zlib.h`, `png.h`, `ogg/*.h`, `vorbis/*.h`

### What's Missing (Why DirectX Headers Can't Parse)

The DirectX headers use COM interface macros that aren't defined:

| Missing Header | Provides | Needed By |
|----------------|----------|-----------|
| `objbase.h` | `STDMETHOD`, `DECLARE_INTERFACE_`, `THIS_`, `PURE`, `IUnknown` | d3d8.h, dsound.h, dinput.h |
| `basetyps.h` | `REFIID`, `GUID` | d3d8.h, dsound.h |
| `guiddef.h` | GUID structure, `DEFINE_GUID` | d3d8.h |
| `minwindef.h` | `DWORD`, `WORD`, `BYTE`, `BOOL`, `HANDLE` | All DirectX headers |
| `ddraw.h` | `DDSURFACEDESC`, `DDPIXELFORMAT` | d3dtypes.h |

### COM Macro Definitions (for reference)

```c
// C interface definitions (from objbase.h)
#define STDMETHOD(method)        HRESULT (STDMETHODCALLTYPE *method)
#define STDMETHOD_(type,method)  type (STDMETHODCALLTYPE *method)
#define PURE
#define THIS_ INTERFACE *This,
#define THIS  INTERFACE *This
#define DECLARE_INTERFACE(iface) \
    typedef interface iface { const struct iface##Vtbl *lpVtbl; } iface; \
    typedef struct iface##Vtbl iface##Vtbl; \
    struct iface##Vtbl
```

---

## VTable Offset Reference

### IDirect3D8 (16 methods)

| Index | Offset (32-bit) | Method |
|-------|-----------------|--------|
| 0 | 0x00 | QueryInterface |
| 1 | 0x04 | AddRef |
| 2 | 0x08 | Release |
| 3 | 0x0C | RegisterSoftwareDevice |
| 4 | 0x10 | GetAdapterCount |
| 5 | 0x14 | GetAdapterIdentifier |
| 6 | 0x18 | GetAdapterModeCount |
| 7 | 0x1C | EnumAdapterModes |
| 8 | 0x20 | GetAdapterDisplayMode |
| 9 | 0x24 | CheckDeviceType |
| 10 | 0x28 | CheckDeviceFormat |
| 11 | 0x2C | CheckDeviceMultiSampleType |
| 12 | 0x30 | CheckDepthStencilMatch |
| 13 | 0x34 | GetDeviceCaps |
| 14 | 0x38 | GetAdapterMonitor |
| 15 | 0x3C | **CreateDevice** |

### IDirect3DDevice8 (97 methods)

| Index | Offset (32-bit) | Method |
|-------|-----------------|--------|
| 0 | 0x00 | QueryInterface |
| 1 | 0x04 | AddRef |
| 2 | 0x08 | Release |
| 3 | 0x0C | TestCooperativeLevel |
| 4 | 0x10 | GetAvailableTextureMem |
| 5 | 0x14 | ResourceManagerDiscardBytes |
| 6 | 0x18 | GetDirect3D |
| 7 | 0x1C | GetDeviceCaps |
| 8 | 0x20 | GetDisplayMode |
| 9 | 0x24 | GetCreationParameters |
| 10 | 0x28 | SetCursorProperties |
| 11 | 0x2C | SetCursorPosition |
| 12 | 0x30 | ShowCursor |
| 13 | 0x34 | CreateAdditionalSwapChain |
| 14 | 0x38 | Reset |
| 15 | 0x3C | Present |
| 16 | 0x40 | GetBackBuffer |
| 17 | 0x44 | GetRasterStatus |
| 18 | 0x48 | SetGammaRamp |
| 19 | 0x4C | GetGammaRamp |
| 20 | 0x50 | **CreateTexture** |
| 21 | 0x54 | CreateVolumeTexture |
| 22 | 0x58 | CreateCubeTexture |
| 23 | 0x5C | CreateVertexBuffer |
| 24 | 0x60 | CreateIndexBuffer |
| 25 | 0x64 | CreateRenderTarget |
| 26 | 0x68 | CreateDepthStencilSurface |
| 27 | 0x6C | CreateImageSurface |
| 28 | 0x70 | CopyRects |
| 29 | 0x74 | UpdateTexture |
| 30 | 0x78 | GetFrontBuffer |
| 31 | 0x7C | SetRenderTarget |
| 32 | 0x80 | GetRenderTarget |
| 33 | 0x84 | GetDepthStencilSurface |
| 34 | 0x88 | **BeginScene** |
| 35 | 0x8C | **EndScene** |
| 36 | 0x90 | **Clear** |
| 37 | 0x94 | SetTransform |
| 38 | 0x98 | GetTransform |
| 39 | 0x9C | MultiplyTransform |
| 40 | 0xA0 | SetViewport |
| 41 | 0xA4 | GetViewport |
| 42 | 0xA8 | SetMaterial |
| 43 | 0xAC | GetMaterial |
| 44 | 0xB0 | SetLight |
| 45 | 0xB4 | GetLight |
| 46 | 0xB8 | LightEnable |
| 47 | 0xBC | GetLightEnable |
| 48 | 0xC0 | SetClipPlane |
| 49 | 0xC4 | GetClipPlane |
| 50 | 0xC8 | **SetRenderState** |
| 51 | 0xCC | GetRenderState |
| 52 | 0xD0 | BeginStateBlock |
| 53 | 0xD4 | EndStateBlock |
| 54 | 0xD8 | ApplyStateBlock |
| 55 | 0xDC | CaptureStateBlock |
| 56 | 0xE0 | DeleteStateBlock |
| 57 | 0xE4 | CreateStateBlock |
| 58 | 0xE8 | SetClipStatus |
| 59 | 0xEC | GetClipStatus |
| 60 | 0xF0 | GetTexture |
| 61 | 0xF4 | **SetTexture** |
| 62 | 0xF8 | GetTextureStageState |
| 63 | 0xFC | **SetTextureStageState** |
| 64 | 0x100 | ValidateDevice |
| 65 | 0x104 | GetInfo |
| 66 | 0x108 | SetPaletteEntries |
| 67 | 0x10C | GetPaletteEntries |
| 68 | 0x110 | SetCurrentTexturePalette |
| 69 | 0x114 | GetCurrentTexturePalette |
| 70 | 0x118 | **DrawPrimitive** |
| 71 | 0x11C | **DrawIndexedPrimitive** |
| 72 | 0x120 | DrawPrimitiveUP |
| 73 | 0x124 | DrawIndexedPrimitiveUP |
| 74 | 0x128 | ProcessVertices |
| 75 | 0x12C | CreateVertexShader |
| 76 | 0x130 | SetVertexShader |
| 77 | 0x134 | GetVertexShader |
| 78 | 0x138 | DeleteVertexShader |
| 79 | 0x13C | SetVertexShaderConstant |
| 80 | 0x140 | GetVertexShaderConstant |
| 81 | 0x144 | GetVertexShaderDeclaration |
| 82 | 0x148 | GetVertexShaderFunction |
| 83 | 0x14C | **SetStreamSource** |
| 84 | 0x150 | GetStreamSource |
| 85 | 0x154 | SetIndices |
| 86 | 0x158 | GetIndices |
| 87 | 0x15C | CreatePixelShader |
| 88 | 0x160 | SetPixelShader |
| 89 | 0x164 | GetPixelShader |
| 90 | 0x168 | DeletePixelShader |
| 91 | 0x16C | SetPixelShaderConstant |
| 92 | 0x170 | GetPixelShaderConstant |
| 93 | 0x174 | GetPixelShaderFunction |
| 94 | 0x178 | DrawRectPatch |
| 95 | 0x17C | DrawTriPatch |
| 96 | 0x180 | DeletePatch |

### IDirectSound8 (12 methods)

| Index | Offset (32-bit) | Method |
|-------|-----------------|--------|
| 0 | 0x00 | QueryInterface |
| 1 | 0x04 | AddRef |
| 2 | 0x08 | Release |
| 3 | 0x0C | **CreateSoundBuffer** |
| 4 | 0x10 | GetCaps |
| 5 | 0x14 | DuplicateSoundBuffer |
| 6 | 0x18 | **SetCooperativeLevel** |
| 7 | 0x1C | Compact |
| 8 | 0x20 | GetSpeakerConfig |
| 9 | 0x24 | SetSpeakerConfig |
| 10 | 0x28 | Initialize |
| 11 | 0x2C | VerifyCertification |

### IDirectSoundBuffer8 (19 methods)

| Index | Offset (32-bit) | Method |
|-------|-----------------|--------|
| 0 | 0x00 | QueryInterface |
| 1 | 0x04 | AddRef |
| 2 | 0x08 | Release |
| 3 | 0x0C | GetCaps |
| 4 | 0x10 | GetCurrentPosition |
| 5 | 0x14 | GetFormat |
| 6 | 0x18 | GetVolume |
| 7 | 0x1C | GetPan |
| 8 | 0x20 | GetFrequency |
| 9 | 0x24 | GetStatus |
| 10 | 0x28 | Initialize |
| 11 | 0x2C | **Lock** |
| 12 | 0x30 | **Play** |
| 13 | 0x34 | SetCurrentPosition |
| 14 | 0x38 | SetFormat |
| 15 | 0x3C | **SetVolume** |
| 16 | 0x40 | SetPan |
| 17 | 0x44 | SetFrequency |
| 18 | 0x48 | **Stop** |
| 19 | 0x4C | **Unlock** |

### IDirectInput8 (10 methods)

| Index | Offset (32-bit) | Method |
|-------|-----------------|--------|
| 0 | 0x00 | QueryInterface |
| 1 | 0x04 | AddRef |
| 2 | 0x08 | Release |
| 3 | 0x0C | **CreateDevice** |
| 4 | 0x10 | EnumDevices |
| 5 | 0x14 | GetDeviceStatus |
| 6 | 0x18 | RunControlPanel |
| 7 | 0x1C | Initialize |
| 8 | 0x20 | FindDevice |
| 9 | 0x24 | EnumDevicesBySemantics |
| 10 | 0x28 | ConfigureDevices |

### IDirectInputDevice8 (26 methods)

| Index | Offset (32-bit) | Method |
|-------|-----------------|--------|
| 0 | 0x00 | QueryInterface |
| 1 | 0x04 | AddRef |
| 2 | 0x08 | Release |
| 3 | 0x0C | GetCapabilities |
| 4 | 0x10 | EnumObjects |
| 5 | 0x14 | GetProperty |
| 6 | 0x18 | SetProperty |
| 7 | 0x1C | **Acquire** |
| 8 | 0x20 | **Unacquire** |
| 9 | 0x24 | **GetDeviceState** |
| 10 | 0x28 | GetDeviceData |
| 11 | 0x2C | **SetDataFormat** |
| 12 | 0x30 | SetEventNotification |
| 13 | 0x34 | **SetCooperativeLevel** |
| 14 | 0x38 | GetObjectInfo |
| 15 | 0x3C | GetDeviceInfo |
| 16 | 0x40 | RunControlPanel |
| 17 | 0x44 | Initialize |
| 18 | 0x48 | CreateEffect |
| 19 | 0x4C | EnumEffects |
| 20 | 0x50 | GetEffectInfo |
| 21 | 0x54 | GetForceFeedbackState |
| 22 | 0x58 | SendForceFeedbackCommand |
| 23 | 0x5C | EnumCreatedEffectObjects |
| 24 | 0x60 | Escape |
| 25 | 0x64 | **Poll** |
| 26 | 0x68 | SendDeviceData |

---

## Decoding Example

In `grim.dll_decompiled.c`, vtable calls look like:
```c
(**(code **)(*DAT_10059dbc + 0x6c))(DAT_10059dbc, ...);
```

To decode:
1. `0x6c / 4 = 27` (index)
2. Look up index 27 in IDirect3DDevice8 table → **CreateImageSurface**

### Known Global Pointers in grim.dll

| Address | Likely Type | Evidence |
|---------|-------------|----------|
| `DAT_10059dbc` | IDirect3DDevice8* | Offsets match device vtable |
| `DAT_1005b2c4` | IDirect3D8* | Used with CreateDevice pattern |
| `DAT_1005c8fc` | IDirect3DTexture8* | Texture operation offsets |

---

## Sources

- [D3D8 Vtable Offsets Gist](https://gist.github.com/Romop5/7ab9d937b5434709301d2529b2ccddda)
- [apitrace/dxsdk d3d8.h](https://github.com/apitrace/dxsdk/blob/master/Include/d3d8.h)
- [elishacloud/DirectX-Wrappers](https://github.com/elishacloud/DirectX-Wrappers)
- [mingw-w64 headers](https://github.com/mingw-w64/mingw-w64/tree/master/mingw-w64-headers/include)
- [Ghidra DirectX parsing discussion #3941](https://github.com/NationalSecurityAgency/ghidra/discussions/3941)
- [Ghidra DirectX issue #1784](https://github.com/NationalSecurityAgency/ghidra/issues/1784)
