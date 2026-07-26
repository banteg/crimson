# Third-party libraries

This page tracks third-party libraries referenced by the Crimsonland binaries
and our current analysis status. The goal is to pin versions so we can align
headers and types with the actual runtime behavior.

`analysis/library_provenance.json` is the machine-readable source of truth for
artifact hashes, embedded ranges, imports, and version fingerprints. Verify it
against the checked-in binaries with:

```sh
uv run crimson match provenance --check
```

Evidence is also listed inline with addresses from the Ghidra and IDA outputs.

## Bundled/embedded libraries (from the game binaries)

### D3DX8 (DirectX 8.1 SDK release archive, 2001-10-16)

- Evidence: both images import `Direct3DCreate8`, but contain D3DX entry points,
  image codecs, math routines, and processor-specific dispatch code internally.

- Evidence: the EXE range `0x00452ef0..0x00460cb8` and the Grim range
  `0x1000aaa6..0x1004b5b0` share large runs of instruction-identical functions
  after image addresses and relocations are normalized.

- Evidence: `float_near_equal`, the 221-byte renderer backend selector, and the
  820-byte matrix inversion routine are independently checked across both
  images by `crimson match provenance`.

- Evidence: the archived Microsoft `DX81SDK_FULL.exe` has SHA-256
  `73f6791e0ae7f8a1d74f71d8ebe517a79c0cbf03fd344424696fd7a3816d2d02`,
  SHA-1 `61b5733209205e942f37431ee40da712e1f50e6a`, and MD5
  `28533018267fa278bb1c603a67d86d2f`. The latter two agree with independent
  historical records.

- Evidence: its `DXF/DXSDK/lib/d3dx8.lib` member has SHA-256
  `39a8e21889a7c1f0b966f04a9e7d392de14ddebb3e091dfa1e5ce3e19564fc28`.
  Exact non-relocated bytes plus recorded COFF relocations match 172 functions
  (40,098 bytes) in the EXE and 683 functions (156,379 bytes) in Grim. Of
  those, 118 EXE functions and 548 Grim functions identify a single archive
  symbol.

- Status: exact DirectX 8.1 SDK archive confirmed for both images. The
  remaining unmatched functions are a boundary/symbol-recovery problem, not a
  reason to recreate D3DX from decompilation.

Reproduce the archive proof without installing the SDK:

```sh
mkdir -p /tmp/crimson-dx81
curl -L -o /tmp/crimson-dx81/DX81SDK_FULL.exe \
  'https://web.archive.org/web/20040108202259id_/http://download.microsoft.com/download/whistler/dx/8.1/W982KMeXP/EN-US/DX81SDK_FULL.exe'
shasum -a 256 /tmp/crimson-dx81/DX81SDK_FULL.exe
unzip -j /tmp/crimson-dx81/DX81SDK_FULL.exe \
  DXF/DXSDK/lib/d3dx8.lib -d /tmp/crimson-dx81

uv run crimson match archive /tmp/crimson-dx81/d3dx8.lib \
  --image game_bins/crimsonland/1.9.93-gog/crimsonland.exe \
  --start 0x00452ef0 --end 0x00460cb8 \
  --expected-sha256 39a8e21889a7c1f0b966f04a9e7d392de14ddebb3e091dfa1e5ce3e19564fc28 \
  --check
uv run crimson match archive /tmp/crimson-dx81/d3dx8.lib \
  --image game_bins/crimsonland/1.9.93-gog/grim.dll \
  --start 0x1000aaa6 --end 0x1004b5b0 \
  --expected-sha256 39a8e21889a7c1f0b966f04a9e7d392de14ddebb3e091dfa1e5ce3e19564fc28 \
  --check
```

### libpng (version 1.0.5)
- Evidence: Grim function `FUN_100103d6` at `0x100103d6` calls
  `png_create_read_struct("1.0.5", ...)`.

- Status: headers imported (`third_party/headers/png_struct_stub.h`).
- Status: public headers synced from libpng v1.0.5 (`third_party/headers/png.h`,
  `third_party/headers/pngconf.h`, `third_party/headers/pngasmrd.h`) for reference.

- Status: the exact `png*.obj` implementations are present in the confirmed
  DirectX 8.1 `d3dx8.lib` and match Grim functions directly.
- Status: png_* signatures mapped (name map).

### zlib (version 1.1.3)
- Evidence: Grim function `FUN_1001c82f` at `0x1001c82f` initializes zlib with
  `"1.1.3"`.

- Evidence: zlib strings report "deflate 1.1.3" and "inflate 1.1.3" at
  `analysis/ghidra/raw/grim.dll_strings.txt:220` and `:221`.

- Status: headers imported (`third_party/headers/zlib.h`, `third_party/headers/zconf.h`).
- Status: the exact zlib objects are present in the confirmed DirectX 8.1
  `d3dx8.lib` and match Grim functions directly.
- Status: mapped core inflate entry points
  (`inflateInit_`/`inflateInit2_`/`inflate`/`inflateReset`/`inflateEnd`).

### libjpeg (IJG 6a)

- Evidence: `grim.dll` contains the release string `6a  7-Feb-96` at
  `0x1004d724` and again at `0x10057754`, followed by the IJG 1996 copyright
  string.

- Status: version is confirmed, correcting the previous 6b-header assumption.
  The currently imported `JPEG_LIB_VERSION 62` headers are 6b and must be
  replaced with the exact 6a release before type/signature synchronization.
- Status: the exact IJG objects are present in the confirmed DirectX 8.1
  `d3dx8.lib`; member symbols such as `jdmarker.obj`, `jmemmgr.obj`, and
  `jquant*.obj` match Grim functions directly.
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

## Platform/SDK dependencies

Imported API versions can be checked from interfaces and call constants.
Statically linked SDK utility code is tracked above and requires archive-member
matching.

### DirectX SDK version (8.1, exact release archive confirmed)
- Evidence: Grim functions including `FUN_10003090` at `0x10003090` call
  `Direct3DCreate8(0xDC)` (`D3D_SDK_VERSION = 220`).

- Evidence: the executable imports and calls `Direct3DCreate8` with the same
  SDK version.

- Evidence: error string explicitly references DirectX 8.1 at
  `analysis/ghidra/raw/grim.dll_strings.txt:435`.

- Evidence: Grim function `FUN_10009a50` at `0x10009a50` and adjacent input
  initialization paths pass version `0x0800` to `DirectInput8Create`.

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

- Match the EXE range `0x00460cb8..0x0046e920` against the exact VC6 CRT
  archive.
- Compare the bundled Xiph DLL hashes against the historical 1.0 Windows
  release bundle, if an authenticated copy is available.
- Replace the imported IJG 6b headers with 6a and map the duplicated codec
  object boundaries.
