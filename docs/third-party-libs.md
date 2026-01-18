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
- Status: png_* signatures mapped (name map).

### zlib (version 1.1.3)
- Evidence: grim.dll initializes zlib with "1.1.3" at
  `analysis/ghidra/raw/grim.dll_decompiled.c:22511`.
- Status: headers imported (`third_party/headers/zlib.h`).
- Status: no signature mapping yet.

### libjpeg (version unknown)
- Evidence: multiple JPEG/JFIF error strings embedded in grim.dll, e.g.
  `analysis/ghidra/raw/grim.dll_strings.txt:11` through `:121`.
- Status: headers imported (`third_party/headers/jpeg_all.h`).
- Status: no signature mapping yet.

### libvorbisfile / libvorbis / libogg (versions unknown)
- Evidence: `vorbisfile.dll` string in `analysis/ghidra/raw/crimsonland.exe_strings.txt:130`.
- Evidence: .ogg asset paths and errors in `analysis/ghidra/raw/crimsonland.exe_strings.txt:884` and later.
- Status: headers imported (`third_party/headers/ogg/ogg.h`,
  `third_party/headers/vorbis/codec.h`, `third_party/headers/vorbis/vorbisfile.h`).
- Status: no signature mapping yet.

## Platform/SDK dependencies (import table)

Versions are not pinned yet; we need to match SDKs/headers by interface GUIDs
and vtable shapes. Evidence comes from Ghidra import discovery.

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
- Identify DirectX 8 SDK build by matching interface GUIDs and vtable sizes
  (D3D8/DInput8/DSound).
- Identify MSVCRT version by import names and CRT string signatures.
- If we ship or bundle `vorbisfile.dll`, compute its hash and extract its
  internal version string.
