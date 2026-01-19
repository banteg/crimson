---
tags:
  - status-tracking
---

# Third-party libraries

This page tracks third-party libraries referenced by the Crimsonland binaries
and our current analysis status. The goal is to pin versions so we can align
headers and types with the actual runtime behavior.

Evidence is listed inline with file paths and line numbers from our Ghidra
outputs.

## Bundled/embedded libraries (from the game binaries)

### libpng (version 1.0.5)
- Evidence: grim.dll calls png_create_read_struct("1.0.5", ...) at
  `analysis/ghidra/raw/grim.dll_decompiled.c:11549`.
- Status: headers imported (`third_party/headers/png_struct_stub.h`).
- Status: public headers synced from libpng v1.0.5 (`third_party/headers/png.h`,
  `third_party/headers/pngconf.h`, `third_party/headers/pngasmrd.h`) for reference.
- Status: png_* signatures mapped (name map).

### zlib (version 1.1.3)
- Evidence: grim.dll initializes zlib with "1.1.3" at
  `analysis/ghidra/raw/grim.dll_decompiled.c:22511`.
- Evidence: zlib strings report "deflate 1.1.3" and "inflate 1.1.3" at
  `analysis/ghidra/raw/grim.dll_strings.txt:220` and `:221`.
- Status: headers imported (`third_party/headers/zlib.h`, `third_party/headers/zconf.h`).
- Status: mapped core inflate entry points (inflateInit_/inflateInit2_/inflate/inflateReset/inflateEnd).

### libjpeg (binary version unknown; headers are IJG 6b)
- Evidence: multiple JPEG/JFIF error strings embedded in grim.dll, e.g.
  `analysis/ghidra/raw/grim.dll_strings.txt:11` through `:121`.
- Evidence (headers): `JPEG_LIB_VERSION 62` (IJG 6b) in
  `third_party/headers/jpeglib.h:33`.
- Evidence (binary): no explicit version string found in grim.dll.
- Status: headers imported (`third_party/headers/jpeg_all.h`).
- Status: no signature mapping yet.

### libvorbisfile / libvorbis / libogg (version 1.0; headers match vorbis v1.0.0 tag)
- Evidence: `vorbisfile.dll` string in `analysis/ghidra/raw/crimsonland.exe_strings.txt:130`.
- Evidence: .ogg asset paths and errors in `analysis/ghidra/raw/crimsonland.exe_strings.txt:884` and later.
- Evidence: bundled DLL hash (sha256) for `game_bins/crimsonland/1.9.93-gog/VORBISFILE.DLL`:
  `f44472c6d9a64045c14583d12c0cfab5b4aa268aceb8bc9e3e1236b3008306f2`.
- Evidence (binary string): `Xiph.Org libVorbis I 20020717` found in
  `game_bins/crimsonland/1.9.93-gog/VORBIS.DLL` (strings offset `0x14460`).
- Evidence (headers): ogg.h `last mod` $Id: ogg.h,v 1.18 2002/07/13$ at
  `third_party/headers/ogg/ogg.h:12`; vorbisfile.h $Id: vorbisfile.h,v 1.17 2002/03/07$
  at `third_party/headers/vorbis/vorbisfile.h:12`; codec.h $Id: codec.h,v 1.40 2002/02/28$
  at `third_party/headers/vorbis/codec.h:12`.
- Evidence (tag match): xiph/vorbis tag v1.0.0 (tagged 2002-07-19) contains identical
  header $Id lines for `include/vorbis/vorbisfile.h` and `include/vorbis/codec.h`.
- Evidence (binary metadata): radare2 `iI` reports VORBISFILE.DLL compiled
  Fri Jul 19 11:35:16 2002 (matches the v1.0.0 tag date).
- Evidence (binary metadata): radare2 `iI` reports OGG.DLL compiled
  Fri Jul 19 11:34:39 2002 and VORBIS.DLL compiled Fri Jul 19 11:34:55 2002.
- Evidence: bundled DLL hashes (sha256) for:
  `game_bins/crimsonland/1.9.93-gog/OGG.DLL` →
  `308540dbd488f3bceca2dbadefe02cf29d10a27c4ac096bb3da053e3e0b923ea`,
  `game_bins/crimsonland/1.9.93-gog/VORBIS.DLL` →
  `b4fa55cfe7547ade0a2d5b800ef085ce20cdd71f61898d2461ea61eb0241812b`.
- Status: headers imported (`third_party/headers/ogg/ogg.h`,
  `third_party/headers/vorbis/codec.h`, `third_party/headers/vorbis/vorbisfile.h`).
- Status: no signature mapping yet.

## Platform/SDK dependencies (import table)

Versions are not pinned yet; we need to match SDKs/headers by interface GUIDs
and vtable shapes. Evidence comes from Ghidra import discovery.

### DirectX SDK version (likely 8.1)
- Evidence: grim.dll calls Direct3DCreate8(0xDC) (D3D_SDK_VERSION = 220) at
  `analysis/ghidra/raw/grim.dll_decompiled.c:993` (also at `:2562`, `:5483`).
- Evidence: crimsonland.exe also calls Direct3DCreate8(0xDC) at
  `analysis/ghidra/raw/crimsonland.exe_decompiled.c:21721`.
- Evidence: error string explicitly references DirectX 8.1 at
  `analysis/ghidra/raw/grim.dll_strings.txt:435`.
- Evidence: DirectInput8Create uses version 0x0800 (DIRECTINPUT_VERSION) at
  `analysis/ghidra/raw/grim.dll_decompiled.c:5950` (also at `:6081`, `:6226`).

### grim.dll imports
- ADVAPI32.DLL, D3D8.DLL, DINPUT8.DLL, GDI32.DLL, KERNEL32.DLL, MSVCRT.DLL,
  URLMON.DLL, USER32.DLL, WINMM.DLL.
- Evidence: `analysis/ghidra/raw/ghidra_analysis.log:28697` through `:28729`.

### crimsonland.exe imports
- ADVAPI32.DLL, D3D8.DLL, DSOUND.DLL, KERNEL32.DLL, OLE32.DLL, OLEAUT32.DLL,
  SHELL32.DLL, URLMON.DLL, USER32.DLL, VERSION.DLL, VORBISFILE.DLL,
  WININET.DLL, WINMM.DLL.
- Evidence: `analysis/ghidra/raw/ghidra_analysis.log:28923` through `:28973`.

## Next evidence to capture
- Optional: verify the exact DirectX 8.1 SDK build by matching interface GUIDs
  and vtable sizes (D3D8/DInput8/DSound).
- Identify MSVCRT version by import names and CRT string signatures.
