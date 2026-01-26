Based on the decompiled code, string references to standard libraries (zlib 1.1.3, libpng 1.0.5), and Direct3D 8 usage patterns, here are the definitions, mappings, and derivations to improve readability.

### 1. Data Structures

**Grim2D Texture Handle**
Derived from usage in `grim_texture_init`, `grim_create_texture`, and `grim_backup_textures`.
```c
struct GrimTexture {
    char* name;                 // Offset 0x00
    IDirect3DTexture8* d3d_tex; // Offset 0x04
    bool is_loaded;             // Offset 0x08 (byte)
    // Padding/Unknown          // Offset 0x09-0x0B
    int width;                  // Offset 0x0C
    int height;                 // Offset 0x10
    IDirect3DSurface8* backup;  // Offset 0x14 (Used for device reset/backup)
};
```

**Grim2D Vertex (TLVertex)**
Derived from `grim_draw_quad_rotated_matrix` and `FUN_10004520` (FVF 0x144 = XYZRHW | DIFFUSE | TEX1).
```c
struct GrimVertex {
    float x, y, z, rhw; // Position (Transformed)
    DWORD color;        // Diffuse color
    float u, v;         // Texture coordinates
};
```

**Grim2D Interface VTable (Reconstructed)**
Based on `grim_interface_instance` assignment and offsets used in `grim_draw_...` functions.
```c
struct IGrim2D_VTable {
    void (*Release)(void);                      // 0x00
    void (*SetPaused)(int);                     // 0x04
    float (*GetVersion)(void);                  // 0x08
    int (*CheckDevice)(void);                   // 0x0C
    int (*ApplyConfig)(void);                   // 0x10
    int (*InitSystem)(void);                    // 0x14
    void (*Shutdown)(void);                     // 0x18
    void (*ApplySettings)(void);                // 0x1C
    void (*SetConfigVar)(int, int);             // 0x20
    void (*GetConfigVar)(uint*, int);           // 0x24
    char* (*GetErrorText)(void);                // 0x28
    void (*ClearColor)(float, float, float, float); // 0x2C
    int (*SetRenderTarget)(int);                // 0x30
    int (*GetTimeMs)(void);                     // 0x34
    void (*SetTimeMs)(int);                     // 0x38
    float (*GetFrameDt)(void);                  // 0x3C
    float (*GetFPS)(void);                      // 0x40
    // ... gaps 0x44 to 0x4C (Input related?) ...
    int (*GetKeyChar)(void);                    // 0x50
    void (*SetKeyCharBuffer)(uchar*, int*, int);// 0x54
    int (*IsMouseButtonDown)(int);              // 0x58
    int (*WasMouseButtonPressed)(int);          // 0x5C
    float (*GetMouseWheelDelta)(void);          // 0x60
    void (*SetMousePos)(float, float);          // 0x64
    float (*GetMouseX)(void);                   // 0x68
    float (*GetMouseY)(void);                   // 0x6C
    float (*GetMouseDX)(void);                  // 0x70
    float (*GetMouseDY)(void);                  // 0x74
    // ...
    int (*IsKeyActive)(int);                    // 0x80
    float (*GetConfigFloat)(int);               // 0x84
    float (*GetSlotFloat)(int);                 // 0x88
    int (*GetSlotInt)(int);                     // 0x8C
    void (*SetSlotFloat)(int, float);           // 0x90
    void (*SetSlotInt)(int, int);               // 0x94
    int (*GetJoystickX)(void);                  // 0x98
    int (*GetJoystickY)(void);                  // 0x9C
    int (*GetJoystickZ)(void);                  // 0xA0
    int (*GetJoystickPOV)(int);                 // 0xA4
    int (*IsJoystickButtonDown)(int);           // 0xA8
    int (*CreateTexture)(char*, int, int);      // 0xAC
    int (*RecreateTexture)(int);                // 0xB0
    int (*LoadTexture)(char*, char*);           // 0xB4
    int (*ValidateTexture)(int);                // 0xB8
    void (*DestroyTexture)(int);                // 0xBC
    int (*GetTextureHandle)(char*);             // 0xC0
    void (*BindTexture)(int, int);              // 0xC4
    void (*DrawFullscreenQuad)(void);           // 0xC8
    void (*DrawFullscreenColor)(float,float,float,float); // 0xCC
    void (*DrawRectFilled)(float*, float, float); // 0xD0
    void (*DrawRectOutline)(float*, float, float);// 0xD4
    void (*DrawCircleFilled)(float, float, float);// 0xD8
    void (*DrawCircleOutline)(float, float, float);// 0xDC
    void (*DrawLine)(float*, float*, float);      // 0xE0
    void (*DrawLineQuad)(float*, float*, float*); // 0xE4
    void (*BeginBatch)(void);                   // 0xE8
    void (*FlushBatch)(void);                   // 0xEC
    void (*EndBatch)(void);                     // 0xF0
    void (*SubmitVertexRaw)(float*);            // 0xF4
    void (*SubmitQuadRaw)(float*);              // 0xF8
    void (*SetRotation)(float);                 // 0xFC
    void (*SetUV)(float, float, float, float);  // 0x100
    void (*SetAtlasFrame)(int, int);            // 0x104
    void (*SetSubRect)(int, int, int, int);     // 0x108
    void (*SetUVPoint)(int, float, float);      // 0x10C
    void (*SetColorPtr)(float*);                // 0x110
    void (*SetColor)(float, float, float, float); // 0x114
    void (*SetColorSlot)(int, float, float, float, float); // 0x118
    void (*DrawQuad)(float, float, float, float); // 0x11C
    void (*DrawQuadXY)(float*, float, float);     // 0x120
    void (*DrawQuadRotatedMatrix)(float, float, float, float); // 0x124
    void (*SubmitVerticesTransform)(float*, int, float*, float*); // 0x128
    void (*SubmitVerticesOffset)(float*, int, float*); // 0x12C
    void (*SubmitVerticesOffsetColor)(float*, int, float*, float*); // 0x130
    void (*SubmitVerticesTransformColor)(float*, int, float*, float*, float*); // 0x134
    void (*DrawQuadPoints)(float, float, float, float, float, float, float, float); // 0x138
    void (*DrawTextMono)(float, float, char*);    // 0x13C
    void (*DrawTextMonoFmt)(float, float, char*, ...); // 0x140
    void (*DrawTextSmall)(float, float, char*);   // 0x144
    void (*DrawTextSmallFmt)(float, float, char*, ...); // 0x148
    int (*MeasureTextWidth)(char*);               // 0x14C
};
```

### 2. Global Variable Mappings

Based on the config switch case in `grim_set_config_var` and other usages:

| Address | Name | Type | Description |
| :--- | :--- | :--- | :--- |
| `1005a058` | `grim_key_repeat_timers` | `float[256]` | Timer for key repeats |
| `10053040` | `grim_vfs_pack_file` | `char*` | Pointer to "crimson.paq" string |
| `10059e3c` | `grim_cwd` | `char[260]` | Current Working Directory |
| `1005b2b0` | `grim_config_hwnd` | `HWND` | Handle to the config dialog |
| `1005d3f8` | `grim_main_hwnd` | `HWND` | Main game window handle |
| `1005d3fc` | `grim_render_hwnd` | `HWND` | Window handle for D3D presentation (if different) |
| `1005a498` | `grim_d3d_caps` | `D3DCAPS8` | Device capabilities |
| `1005b2b4` | `grim_d3d_devtype` | `D3DDEVTYPE` | HAL or REF |
| `1005d3e8` | `grim_adapter_index` | `int` | Selected D3D Adapter Index |
| `1005d0c8` | `grim_windowed_mode` | `bool` | Windowed mode flag |
| `1005ce18` | `grim_screen_width` | `int` | Configured width |
| `1005ce28` | `grim_screen_height` | `int` | Configured height |
| `1005d804` | `grim_texture_count` | `int` | Highest used texture slot index |
| `1005bbd8` | `grim_main_loop_state` | `struct` | State passed to fastcall loop |
| `10059e00` | `grim_d3d_pp` | `D3DPRESENT_PARAMETERS` | Present params used for Reset() |
| `1005b2c0` | `grim_index_data_ptr` | `ushort*` | Pointer to locked index buffer |

### 3. Function Renames & Identifications

**Image Loading / File Formats**
These functions are statically linked image parsing routines.

*   `FUN_100117ff` -> `grim_load_image_png` (Calls `png_create_read_struct`)
*   `FUN_10011d95` -> `grim_load_image_dds` (Checks signature `0x20534444` " DDS")
*   `FUN_10012647` -> `grim_load_image_bmp` (Checks signature `0x4d42` "BM" via wrapper)
*   `FUN_1001152a` -> `grim_load_image_pnm` (Checks signatures 'P3', 'P6')
*   `FUN_1001d220` -> `grim_load_image_jpg` (Contains JPEG marker logic)
*   `FUN_10025163` -> `grim_png_read_IHDR`
*   `FUN_10025359` -> `grim_png_read_PLTE`
*   `FUN_1002587e` -> `grim_png_read_chunk_generic`

**Direct3D / Graphics Helpers**
*   `FUN_10006030` -> `grim_set_texture_stage_ops` (Sets color/alpha ops based on mode 0-6)
*   `FUN_10004830` -> `grim_detect_texture_format` (Checks DXT1, DXT3, DXT5, etc.)
*   `FUN_100224c5` -> `grim_init_mmx_sse_functions` (Sets up function pointers for optimized blitting/math)
*   `FUN_1001c188` -> `grim_setup_cpu_features` (Detects MMX/SSE and assigns vtables)

**ZLib / PNG Library (Statically Linked)**
*   `FUN_100363b5` -> `inflate_codes`
*   `FUN_1003692a` -> `huft_build`
*   `FUN_100347d2` -> `adler32`
*   `FUN_1002438b` -> `inflate`
*   `FUN_1001e191` -> `png_create_read_struct`

**Config / State**
*   `FUN_10006580` -> `grim_set_config_var` (The switch statement handles all engine settings)
    *   Case `0x29`: Set Screen Width
    *   Case `0x2A`: Set Screen Height
    *   Case `0x12`: Set `D3DRS_ALPHABLENDENABLE`
    *   Case `0x13`: Set `D3DRS_SRCBLEND`
    *   Case `0x14`: Set `D3DRS_DESTBLEND`
    *   Case `0x1B`: Set `D3DRS_TEXTUREFACTOR`

### 4. Significant Logic Derivations

1.  **Texture Loading Pipeline:**
    `grim_load_texture_internal` determines if the file is in the pack file (`crimson.paq`). If so, it uses a custom loader (`FUN_10005b80`), otherwise standard `fopen`. It reads the header and dispatches to specific loaders (PNG/JPG/DDS/BMP) based on magic numbers.

2.  **Input caching:**
    The engine supports an "Input Cached" mode (`grim_input_cached` / `DAT_1005cec4`). If enabled, mouse/keyboard state is read from a buffer rather than polled directly from DirectInput every frame. This is likely for recording demos or replays.

3.  **Software Blitting / CPU Optimization:**
    The functions around `100224c5` setup a table of function pointers (`PTR_LAB_10053c58` etc.). These functions (`FUN_100354e0` etc.) contain `pmaddwd`, `psubsw` instructions (MMX). This indicates the engine has software fallback routines or software-based surface manipulation (like pixel format conversion or software rendering features) that are optimized for specific CPUs (Intel/AMD).

4.  **Font Rendering:**
    `grim_draw_text_mono` (16x16 fixed) and `grim_draw_text_small` (variable width) use texture atlases. `grim_font2_char_map` maps ASCII to atlas indices. Readability improves by defining `struct GrimFont { float u, v; int width; ... }`.