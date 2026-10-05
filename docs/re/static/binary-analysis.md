---
tags:
  - status-analysis
---

# Binary Analysis

Static analysis findings for `crimsonland.exe` and `grim.dll` to aid decompilation.

## Build Information

| Property | crimsonland.exe | grim.dll |
|----------|-----------------|----------|
| Final linker | Visual C++ 6, `Linker600` 6.00.8447 | Visual C++ 6, `Linker600` 6.00.8447 |
| Compiler inputs | VC6 `Utc12` plus VC7-generation provider objects | VC6 `Utc12` plus VC7-generation provider objects |
| PE timestamp | 2011-02-01 07:13:37 UTC | 2011-02-01 07:25:24 UTC |
| Image base | 0x00400000 (fixed) | 0x10000000 |
| Entry point | 0x00463026 | 0x1000a9e9 |
| Subsystem | GUI (Windows) | GUI (Windows) |
| Relocations | None | 5738 HIGHLOW |

**Original build path:** `..\grim_grSystem_c\Release\grim.dll`

### Toolchain provenance

The former VC++ 7.1 attribution on this page was an early heuristic and is
superseded by object-level evidence:

- the executable's optional-header linker version is 6.0;
- its Rich header contains product-10/product-11 build-9782 records consistent
  with the VC6 SP6 code generator;
- product-28/product-29 build-9178 records identify VC7-generation objects
  produced by the Windows XP DDK's 13.00.9176/9178 compiler, while product 25
  build 9210 is `Implib700` metadata rather than the final linker;
- the exact pinned DirectX 8.1 `d3dx8.lib` carries those build-9178 compiler
  records and matches the native D3DX ranges, establishing library-provider
  ancestry without implying a partial game-source migration;
- controlled Processor Pack objects use product 48/49 build 9044, which is
  absent from the executable; and
- the build-8047 records in `grim.dll` can be reproduced from members of the
  VC6 SP6 `msvcrt.lib` archive, so they do not identify an 8047 engine-code
  frontend.

An authentic VS6 RTM compile reports build 8168, ruling out RTM as a hidden
8047 compiler. Corpus-wide comparison also produces identical output from the
available 8966 and 9782 optimizers across all current Crimsonland and Grim
scratches. The exact XP-DDK build-9178 compiler closes four historical D3DX
source controls, but produces no exact or improved result across the current
61 game-owned WIPs. Matching therefore uses `msvc6.5 /O2 /GB` as the compact
canonical profile; alternate compiler profiles are search controls, not
provenance claims.

See `tools/match/README.md` in the repository for the compiler inventory,
hashes, Rich-header controls, and current corpus comparison.

## Security Features (None)

- No debug symbols (PDB stripped)
- No RTTI (C++ class names not embedded)
- No SafeSEH
- No ASLR
- No DEP/NX
- No stack canaries

## Sections

### crimsonland.exe

| Section | VA | Virtual Size | Raw Size | Flags |
|---------|-----|--------------|----------|-------|
| .text | 0x401000 | 448,888 | 450,560 | CODE, EXEC, READ |
| .rdata | 0x46f000 | 7,776 | 8,192 | INIT_DATA, READ |
| .data | 0x471000 | 435,448 | 57,344 | INIT_DATA, READ, WRITE |
| .rsrc | 0x4dd000 | 7,000 | 8,192 | INIT_DATA, READ |

Note: 378KB of `.data` is uninitialized (BSS) - global game state arrays.

### grim.dll

| Section | VA | Virtual Size | Raw Size | Flags |
|---------|-----|--------------|----------|-------|
| .text | 0x10001000 | 306,153 | 307,200 | CODE, EXEC, READ |
| .rdata | 0x1004c000 | 25,950 | 28,672 | INIT_DATA, READ |
| .data | 0x10053000 | 44,020 | 28,672 | INIT_DATA, READ, WRITE |
| .rsrc | 0x1005f000 | 190,392 | 192,512 | INIT_DATA, READ |
| .reloc | 0x1008e000 | 14,026 | 16,384 | INIT_DATA, READ |

## Exports

### grim.dll

Single export:
```
GRIM__GetInterface @ 0x100099c0
```

This returns a pointer to the Grim2D interface vtable.

## Key Imports

### crimsonland.exe

| DLL | Functions | Purpose |
|-----|-----------|---------|
| d3d8.dll | Direct3DCreate8 | Graphics (via grim.dll) |
| DSOUND.dll | ordinal 11 (DirectSoundCreate8) | Audio output |
| vorbisfile.dll | ov_read, ov_open_callbacks, ov_info, ov_clear, ov_pcm_total, ov_pcm_seek | OGG audio decoding |
| WININET.dll | InternetOpenA, HttpSendRequestA, etc. | Online high scores |
| VERSION.dll | GetFileVersionInfoA, VerQueryValueA | Version checking |

### grim.dll

| DLL | Functions | Purpose |
|-----|-----------|---------|
| d3d8.dll | Direct3DCreate8 | Direct3D 8 rendering |
| DINPUT8.dll | DirectInput8Create | Keyboard/mouse input |
| urlmon.dll | HlinkNavigateString | Open URLs in browser |

## Embedded Resources

### grim.dll

| ID | Type | Size | Content |
|----|------|------|---------|
| 111 (0x6f) | RT_RCDATA | 93,162 | Mono font TGA 512×496 (`default_font_courier.tga`) |
| 113 (0x71) | RT_RCDATA | 7,026 | Splash logo TGA 128×128 |
| 144 | RT_BITMAP | 74,024 | "CRIMSONLAND" title 385×64 |
| 145 | RT_BITMAP | 8,776 | "RealOne Arcade" logo 104×28 |
| 116, 137-140 | RT_DIALOG | ~2KB | Config dialog templates |
| 1, 2 | RT_ICON | 4.5KB | Application icons |

### crimsonland.exe

| ID | Type | Size | Content |
|----|------|------|---------|
| 102 | RT_BITMAP | 1,256 | Small bitmap 48×48 |
| 1, 2 | RT_ICON | 4.5KB | Application icons |
| 101 | RT_DIALOG | 854 | Dialog template |

## VTables

### grim.dll

| Address | Entries | Purpose |
|---------|---------|---------|
| 0x1004c238 | 84 | **Grim2D public interface** `grim_interface_vtable` (see [Grim2D API](../../grim2d/api.md)) |
| 0x1004cae4 | 4 | `grim_vertex_space_converter_vtable` |
| 0x1004caf8–0x1004cdf0 | 4 each | 39 pixel-format vtables (`grim_pixel_format_vtable_*`, e.g. `_r8g8b8` at 0x1004cb6c, `_x1r5g5b5` at 0x1004cbdc, `_a4r4g4b4` at 0x1004cc10), one installed by each pixel-format constructor |

### crimsonland.exe

| Address | Entries | Purpose |
|---------|---------|---------|
| 0x0046f3e4 | 34 | `mod_api_vtable`: the `clAPI` virtuals exposed to mods (`mod_api_vtbl_t`) |

## Embedded Libraries

### grim.dll

The image codecs come from the statically linked DirectX 8.1 `d3dx8.lib`
(0x1000aaa6–0x1004b5b0); Grim decodes image files through the D3DX texture
loaders (`decomp/1.9/grim/texture/load_file.cpp`). The archive carries:

- **IJG libjpeg 6a** (`"6a  7-Feb-96"` at 0x1004d724)
- **libpng 1.0.5** (`"1.0.5"` at 0x1004e1c0)
- **zlib 1.1.3** (`"deflate 1.1.3"` / `"inflate 1.1.3"` at 0x10050971 / 0x100514a1)

Archive and version provenance is pinned in `analysis/library_provenance.json`;
[Native linking](native-linking.md) describes how the archives are rebuilt and
linked.

## Identified Strings

### C++ Class Names

Only one C++ method name found (no RTTI):
```
MyApp::Init  (grim.dll @ 0x05384e)
```

### Grim2D Internal Names

```
GRIM__GetInterface  @ 0x05254b
GRIM_Font2          @ 0x053c3c
```

### Registry Keys

```
Software\10tons\Crimsonland\        @ 0x073a6c
Software\10tons entertainment\Crimsonland  @ 0x074604
```

### Network

```
http://buy.crimsonland.com  @ 0x071b40
www.crimsonland.com         @ 0x075584
```

## Function inventory

The exact function inventory, with each function's recovered source or library
archive and its byte-match proof, is the match report
`analysis/decomp/1.9.93.json`.

## Useful Addresses for Decompilation

### crimsonland.exe

| Address | Content |
|---------|---------|
| 0x071164 | Console `exec` command string |
| 0x071228 | Console `quit` command string |
| 0x071230 | Console `set` command string |
| 0x0712d0 | Version string "1.9.93" |
| 0x0785c8 | "Initializing Grim" log message |
| 0x073794 | "FAILED Loading uiElement" error |

### grim.dll

| Address | Content |
|---------|---------|
| 0x100099c0 | `GRIM__GetInterface` export |
| 0x1004c238 | Grim2D vtable (84 entries) |
| 0x053618 | D3D error message prefix |
| 0x05384e | "MyApp::Init" string |
