---
tags:
  - status-tracking
---

# Binary Analysis

Static analysis findings for `crimsonland.exe` and `grim.dll` to aid decompilation.

## Build Information

| Property | crimsonland.exe | grim.dll |
|----------|-----------------|----------|
| Compiler | Visual Studio 2003 (VC++ 7.1 SP1) | Visual Studio 2003 (VC++ 7.1 SP1) |
| Build date | 2011-02-01 07:13:37 UTC | 2011-02-01 07:25:24 UTC |
| Image base | 0x00400000 (fixed) | 0x10000000 |
| Entry point | 0x00463026 | 0x1000a9e9 |
| Subsystem | GUI (Windows) | GUI (Windows) |
| Relocations | None | 5738 HIGHLOW |

**Original build path:** `..\grim_grSystem_c\Release\grim.dll`

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
| 0x1004c238 | 84 | **Grim2D public interface** (documented in grim2d-api.md) |
| 0x1004cc10 | 124 | Texture format converter table (31 groups × 4 methods) |
| 0x1004cb6c | 20 | Unknown |
| 0x1004cbdc | 8 | Unknown |

### crimsonland.exe

| Address | Entries | Purpose |
|---------|---------|---------|
| 0x0046f3e4 | 34 | Likely switch/dispatch table |

## Embedded Libraries

### grim.dll

Statically linked image libraries:
- **libjpeg** (IJG) - JPEG decoding
- **libpng** - PNG decoding  
- **zlib** - Deflate compression

Evidence: Library signature strings found at:
- libjpeg: 0x04d0e9 ("JFIF")
- libpng: 0x04e29d
- zlib: 0x04e24c, deflate/inflate at 0x050971/0x0514a1

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

## Function Estimation

### By prologue patterns

| Binary | `push ebp; mov ebp,esp` | `ret` instructions |
|--------|-------------------------|-------------------|
| crimsonland.exe | 244 | 2221 |
| grim.dll | 356 | 1660 |

Note: Lower than Ghidra's count because many functions use different calling conventions or are inlined.

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

## Notes for Ghidra

1. **No RTTI** - Class names must be inferred from usage patterns
2. **VS2003 compiler** - Use Microsoft demangler for any mangled names
3. **Fixed base for exe** - No relocations, addresses are final
4. **DLL has relocations** - 5738 entries, useful for identifying code vs data references
5. **Large BSS in exe** - 378KB uninitialized, contains runtime game state arrays
