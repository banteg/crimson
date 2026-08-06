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

- Native provider: both images now link the pinned archive.
  Crimsonland resolves its recovered `vec2_normalize_dispatch` name to the
  exact `D3DXVec2Normalize` thunk and initializer in `d3dxmath.obj`; the
  selected graph retains six additional KERNEL32/ADVAPI32 imports already
  present in the reference executable and eliminates the last non-platform
  executable placeholder. Grim links `D3DXCreateTexture`, both
  `D3DXCreateTextureFromFile*` entrypoints, `D3DXVec2Normalize`, and the
  byte-identical internal
  `D3DXComputeNormalMap` body (`0x1000b3fe`, 2,046 bytes and 52 normalized
  relocations). Its 24 decorated platform dependencies are modeled separately
  from closure coverage; release dead-code elimination retains 17 imports
  found in the reference DLL and discards the other seven.

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

### Visual C++ 6.0 SP6 runtime

- Evidence: `VS6sp61.cab` from preserved Visual Studio 6 SP6 media contains
  `vc98/lib/libcmt.lib` with SHA-256
  `a541c95e5ffdd6d5573d1976f5e5d0038f2c4fb0bcb02975c68948bf1d6e452a`
  and `vc98/lib/msvcrt.lib` with SHA-256
  `3efc3ddf045a459a2b6403f0b821be2cb7c316ffca67dddddb346cea7a9e4f63`.

- Evidence: exact non-relocated bytes plus COFF relocations match 299 of 366
  functions (43,754 of 54,038 bytes) in the EXE range
  `0x00460cb8..0x0046e920`. Of those, 254 functions (41,813 bytes) identify a
  single `LIBCMT.LIB` symbol. The SP6 single-threaded `LIBC.LIB` matches only
  203 functions (29,886 bytes), confirming the multithreaded static flavor.

- Evidence: `LIBCMT.LIB` identifies 15 of 17 functions in Grim's
  `0x1000a8d0..0x1000aaa6` runtime/import seam. The two substantive unique
  matches are `dllcrt0.obj:__DllMainCRTStartup@12` and
  `onexit.obj:_atexit`; Grim imports `MSVCRT.DLL`, so this is startup glue
  rather than a second statically linked CRT body.

- Evidence: the DLL-flavor `MSVCRT.LIB` is the stronger provider match for
  Grim. It uniquely matches 4 of 17 functions (390 of 468 bytes):
  `atonexit.obj:__onexit`, `atonexit.obj:_atexit`,
  `crtdll.obj:__CRT_INIT@12`, and
  `crtdll.obj:__DllMainCRTStartup@12`. Its 308-byte `dllsupp.obj` defines
  absolute `__except_list=0` and `__fltused=0x9876`, exactly the two
  toolchain externals required by the native link.

- Evidence: a whole-image Grim link with this pinned archive resolves all 15
  configured MSVCRT imports, `_atexit`, `__except_list`, and `__fltused`.
  The game object's nonstandard `_strdup` reference is a weak COFF alias to
  the archive's `__strdup` thunk, preserving the reference PE import name
  `_strdup` without inventing a CRT body.

- Evidence: `crimsonland.exe` contains 137 product-10/build-9782 C records and
  34 product-11/build-9782 C++ records. Controlled Processor Pack compiles emit
  product 48 and 49 with build 9044, and a stock VC6 link preserves those
  records; neither occurs in the EXE. This supports VC6 SP6 code-generator
  ancestry rather than a hidden per-object Processor Pack split.

- Evidence: `MSVCRT.LIB` itself contains build-8047 Rich inputs: 3 product-4
  linker members, 26 product-10 C members, and 4 product-11 C++ members. A
  structural Grim relink through the pinned archive reproduces the reference's
  exact product-4/build-8047 count of 2 and product-11/build-8047 count of 2,
  plus 1 of its 4 product-10/build-8047 records. The aggregate 8047 records
  therefore demonstrate provider ancestry, not a second engine compiler.

- Evidence: authentic June 1998 Visual Studio 6 Enterprise RTM media
  (`VSE600ENU1.ISO`, SHA-256
  `a670cfb0a5ba6c89c2aa32fd884f21fa348e72cad9d4378b63d08e9da1708f15`)
  emits `@comp.id=0x000b1fe8` for a controlled C++ object, identifying the
  RTM frontend as build 8168 rather than 8047.

- Status: the EXE's static CRT archive and Grim's DLL CRT provider are
  archive-confirmed. The Grim provider now participates in the structural
  whole-image link. Grim engine code remains in scope through `0x1000a8d0`;
  in particular, the JAZ/zlib helpers at `0x1000a810..0x1000a8c2` do not
  match D3DX or either CRT archive.

Reproduce the archive proof:

```sh
mkdir -p /tmp/crimson-vc6
curl -L -o /tmp/crimson-vc6/vs6sp6.iso.zip \
  'https://archive.org/download/vs6.iso/vs6sp6.iso.zip'
shasum -a 256 /tmp/crimson-vc6/vs6sp6.iso.zip
unzip -j /tmp/crimson-vc6/vs6sp6.iso.zip -d /tmp/crimson-vc6
7z e /tmp/crimson-vc6/vs6sp6.iso VS6sp61.cab -o/tmp/crimson-vc6
cabextract -F vc98/lib/libcmt.lib -d /tmp/crimson-vc6 \
  /tmp/crimson-vc6/VS6sp61.cab
cabextract -F vc98/lib/msvcrt.lib -d /tmp/crimson-vc6 \
  /tmp/crimson-vc6/VS6sp61.cab

uv run crimson match archive /tmp/crimson-vc6/vc98/lib/libcmt.lib \
  --image game_bins/crimsonland/1.9.93-gog/crimsonland.exe \
  --start 0x00460cb8 --end 0x0046e920 \
  --expected-sha256 a541c95e5ffdd6d5573d1976f5e5d0038f2c4fb0bcb02975c68948bf1d6e452a \
  --check
uv run crimson match archive /tmp/crimson-vc6/vc98/lib/libcmt.lib \
  --image game_bins/crimsonland/1.9.93-gog/grim.dll \
  --start 0x1000a8d0 --end 0x1000aaa6 \
  --expected-sha256 a541c95e5ffdd6d5573d1976f5e5d0038f2c4fb0bcb02975c68948bf1d6e452a \
  --check
uv run crimson match archive /tmp/crimson-vc6/vc98/lib/msvcrt.lib \
  --image game_bins/crimsonland/1.9.93-gog/grim.dll \
  --start 0x1000a8d0 --end 0x1000aaa6 \
  --expected-sha256 3efc3ddf045a459a2b6403f0b821be2cb7c316ffca67dddddb346cea7a9e4f63 \
  --show-matches --check
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
- Status: the confirmed DirectX 8.1 `d3dx8.lib` contains its namespaced zlib
  copy, while the JAZ path calls a separate plain-C copy.
- Status: mapped core inflate entry points
  (`inflateInit_`/`inflateInit2_`/`inflate`/`inflateReset`/`inflateEnd`).
- Native provider: stock zlib 1.1.3 compiled with VC6
  `/O2 /GB /W3 /MD` reproduces `_uncompress` at `0x10046400` byte-for-byte
  (156 bytes, five relocations). The deterministic full archive matches 24
  Grim functions totaling 13,441 bytes and has SHA-256
  `6b44ac2a8a67123b929cb9286c343730af5f6777609a54e12e402e5ac7e503b0`.
- Matcher corpus: the pinned upstream `uncompr.c` is synced byte-for-byte and
  provenance checked. Its normal scratch compile reproduces all 52 instructions
  and all five references at `0x10046400`.
- Matcher corpus: the pinned `adler32.c`, `zutil.c`, and private `zutil.h`
  sources reproduce the plain-C `adler32`, `zcalloc`, and `zcfree` bodies at
  `0x10049190`, `0x10047a00`, and `0x10047a20`. Together they add 335 exact
  bytes and keep both CRT import references audited.

### libjpeg (IJG 6a)

- Evidence: `grim.dll` contains the release string `6a  7-Feb-96` at
  `0x1004d724` and again at `0x10057754`, followed by the IJG 1996 copyright
  string.

- Status: version is confirmed, correcting the previous 6b-header assumption.
  `jpeglib.h`, `jmorecfg.h`, `jerror.h`, and `jpegint.h` are now synced
  byte-for-byte from the IJG 6a source archive (`JPEG_LIB_VERSION 61`).
- Status: the exact IJG objects are present in the confirmed DirectX 8.1
  `d3dx8.lib`; member symbols such as `jdmarker.obj`, `jmemmgr.obj`, and
  `jquant*.obj` match Grim functions directly.
- Status: the interleaved plain-C decompressor entry cluster at
  `0x10009a50..0x1000a107` is mapped as `jpeg_CreateDecompress`,
  `jpeg_destroy_decompress`, `jpeg_read_header`, `jpeg_consume_input`,
  `default_decompress_parms`, `jpeg_finish_decompress`,
  `jpeg_start_decompress`, `output_pass_setup`, and `jpeg_read_scanlines`.
  These nine library functions are excluded from the default port score with
  address-keyed `third-party` dispositions. They are a separately linked JAZ
  decoder copy: the confirmed D3DX8 archive exposes namespaced symbols with
  byte-distinct entry bodies elsewhere in Grim, so this cluster remains a
  separate provider target.
- Native provider: IJG's documented Windows compatibility choice
  `typedef unsigned char boolean` reproduces Grim's `0x1a8`
  `jpeg_decompress_struct` ABI. With that build configuration, stock IJG 6a
  compiled with VC6 `/O2 /GB /W3 /MD` exactly matches all nine entry-cluster
  functions (1,642 bytes total). `jdmarker.c`, `jcomapi.c`, and the recovered
  custom memory source use `/O2 /G6 /W3 /MD`.
- Native provider: `grim_jpeg_memory_src` at `0x1003a990` and its four local
  callbacks at `0x1003aa10..0x1003ab00` are exact matches totaling 354 bytes.
  The recipe additionally gates exact `jpeg_resync_to_restart`, `jpeg_abort`,
  and `jpeg_destroy` bodies. Across the archive, 18 functions are required to
  match their reference addresses before publication.
- Matcher corpus: the pinned IJG 6a `jinclude.h` is synced and provenance
  checked alongside the public headers. All five memory-source functions now
  select the canonical provider translation unit directly under its VC6
  profile and documented one-byte `boolean` ABI, yielding 354 exact all-scope
  bytes without duplicating the recovered source.
- Matcher corpus: the private `jdct.h` header plus the official `jidctred.c`
  and `jidctflt.c` units are also synced and provenance checked. They recover
  the exact one-pixel and floating-point IDCT bodies; two small matcher-only
  dispatchers recover D3DX's aligned portable/MMX integer routing. The 4-by-4
  and 2-by-2 reducers remain explicit semantic-complete compiler residuals.
- Native provider: the normalized 28-object archive has size 152,452 and
  SHA-256
  `c0bf240e27e8684357c676030e3cb8913d04e6b1e14f8000f069b43b17de6869`.
- Native provider: `jpeg_std_error` at `0x1003ab10` is a 76-byte exact match
  for `obj\i386\jerror.obj` in the pinned DirectX 8.1 archive and links
  through an evidence-backed weak alias to its namespaced D3DX symbol.
- Status: every JAZ libjpeg closure entry and zlib's `_uncompress` are now
  archive-backed; the JAZ provider has no remaining placeholder symbols.
- Status: `grim_jaz_jpeg_error_exit` remains a 100% scratch match with the 6a
  headers. It and the surrounding JAZ payload/RLE logic remain Grim-owned.

Rebuild both open-source provider archives from the pinned releases:

```sh
curl -L -o /tmp/jpegsrc.v6a.tar.gz \
  https://www.ijg.org/files/jpegsrc.v6a.tar.gz
curl -L -o /tmp/zlib-1.1.3.tar.gz \
  https://zlib.net/fossils/zlib-1.1.3.tar.gz

uv run python scripts/build_native_codec_providers.py \
  --jpeg-tar /tmp/jpegsrc.v6a.tar.gz \
  --zlib-tar /tmp/zlib-1.1.3.tar.gz
```

The recipe verifies both source hashes, the VC6/Wibo tool hashes, the
normalized output hashes, 18 required libjpeg address matches, and zlib's
`uncompress` match before publishing either ignored archive.

### libvorbisfile / libvorbis / libogg (Ogg Vorbis Win32 SDK 1.0)
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

- Evidence: the archived official `OggVorbis-win32sdk-1.0.zip` has SHA-256
  `e40f25803224ce4fee102e74d97c1bf77231986a9acc33eb613232e860fee7fe`.
  Its `ogg.dll`, `vorbis.dll`, and `vorbisfile.dll` members are byte-for-byte
  identical to all three DLLs shipped with Crimsonland.

- Status: headers imported (`third_party/headers/ogg/ogg.h`,
  `third_party/headers/vorbis/codec.h`, `third_party/headers/vorbis/vorbisfile.h`).
  They are content-identical to the SDK headers after normalizing CRLF to LF.

- Status: exact Windows binary release confirmed; no signature mapping yet.

Reproduce the binary proof:

```sh
mkdir -p /tmp/crimson-xiph
curl -L -o /tmp/crimson-xiph/OggVorbis-win32sdk-1.0.zip \
  'https://web.archive.org/web/20030403114946id_/http://www.vorbis.com/files/1.0/windows/OggVorbis-win32sdk-1.0.zip'
shasum -a 256 /tmp/crimson-xiph/OggVorbis-win32sdk-1.0.zip
unzip -j /tmp/crimson-xiph/OggVorbis-win32sdk-1.0.zip \
  'oggvorbis-win32sdk-1.0/bin/*.dll' -d /tmp/crimson-xiph
cmp game_bins/crimsonland/1.9.93-gog/ogg.dll /tmp/crimson-xiph/ogg.dll
cmp game_bins/crimsonland/1.9.93-gog/vorbis.dll /tmp/crimson-xiph/vorbis.dll
cmp game_bins/crimsonland/1.9.93-gog/vorbisfile.dll \
  /tmp/crimson-xiph/vorbisfile.dll
```

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

- Evidence: Grim joystick, keyboard, and mouse initialization paths at
  `0x1000a1c0`, `0x1000a390`, and `0x1000a5a0` pass version `0x0800` to
  `DirectInput8Create`.

### grim.dll imports
- ADVAPI32.DLL, D3D8.DLL, DINPUT8.DLL, GDI32.DLL, KERNEL32.DLL, MSVCRT.DLL,
  URLMON.DLL, USER32.DLL, WINMM.DLL.

- Evidence: `analysis/ghidra/raw/ghidra_analysis.log:28697` through `:28729`.

### crimsonland.exe imports
- ADVAPI32.DLL, D3D8.DLL, DSOUND.DLL, KERNEL32.DLL, OLE32.DLL, OLEAUT32.DLL,
  SHELL32.DLL, URLMON.DLL, USER32.DLL, VERSION.DLL, VORBISFILE.DLL,
  WININET.DLL, WINMM.DLL.

- Evidence: `analysis/ghidra/raw/ghidra_analysis.log:28923` through `:28973`.
