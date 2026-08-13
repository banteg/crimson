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

- Evidence: the archive's COFF members contain 134 `Utc13_CPP` product-29
  build-9178 records, one `Utc13_C` product-28 build-9178 record, one older
  product-28 build-8685 record, and one product-18 build-8444 assembly record.
  The exact Windows XP DDK 5.1.2600 x86 compiler has C1/C1XX 13.00.9176, C2
  13.00.9178, and LINK/ML 7.00.9210. This identifies the archive's 9178 code as
  XP-DDK/VC7-generation provider output, not a VC6 C2 stamp or evidence of a
  partial game-source migration.

- Evidence: product 25 build 9210 is `Implib700` metadata from the same VC7
  tool generation. The final images instead record `Linker600` product 4 build
  8447 and optional-header linker version 6.0, so VC7-generated input objects
  and a VC6 final link are compatible rather than contradictory.

- Status: exact DirectX 8.1 SDK archive confirmed for both images. The
  remaining unmatched functions are a boundary/symbol-recovery problem, not a
  reason to recreate D3DX from decompilation.

- Status: the exact build-9178 compiler was replayed against the four faithful
  IJG source reconstructions that previously differed only in byte-clear or
  independent-store scheduling. All four now compile byte-exact (1,285 bytes,
  453 instructions, and 19 resolved references). Their archive-member
  scratches remain canonical because they preserve the original objects
  directly. The same compiler produced no exact or improved profile across
  the 61 current game-owned WIPs.

- Native provider: both images now link the pinned archive.
  Crimsonland resolves its recovered `D3DXVec2Normalize` name to the
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

When harvesting new archive scratches, add `--missing-scratches` to evaluate
the all-scope scratch set and exclude every target address that already has a
scratch. The text and JSON reports include the excluded function and byte
counts; combine it with `--show-matches --json` and select `matches[].unique`
for the remaining uniquely attributable provider functions.

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
- Evidence: Grim function `d3dx_image_load_dib` at `0x100103d6` calls
  `d3dx_png_create_read_struct("1.0.5", ...)`.

- Status: headers imported (`third_party/headers/png_struct_stub.h`).
- Status: public headers synced from libpng v1.0.5 (`third_party/headers/png.h`,
  `third_party/headers/pngconf.h`, `third_party/headers/pngasmrd.h`) for reference.

- Status: the exact `png*.obj` implementations are present in the confirmed
  DirectX 8.1 `d3dx8.lib` and match Grim functions directly.
- Status: png_* signatures mapped (name map).

### zlib (version 1.1.3)
- Evidence: Grim function `d3dx_jpeg_get_soi` at `0x1001c82f` initializes zlib with
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
- Matcher corpus: the pinned inflate-private headers and `infutil.c` reproduce
  `inflate_flush` at `0x1004b0e0` byte-for-byte (306 bytes, 117 instructions).
  These headers also establish the original state layouts for subsequent
  source-backed recovery of the remaining plain-C inflate modules.
- Matcher corpus: the pinned upstream `inflate.c` reproduces `inflateEnd`,
  `inflateInit2_`, `inflateInit_`, and `inflate` at `0x100473f0` through
  `0x100475d0` byte-for-byte (1,477 bytes, 550 instructions). The initializer's
  `/Ob2` profile accounts for the observed automatic inlining of `inflateEnd`
  and `inflateReset`; all 17 direct references across the four functions are
  resolved to the separate plain-C zlib copy.
- Matcher corpus: the pinned `inffast.c` and private `inffast.h` reproduce
  `inflate_fast` at `0x1004b220` byte-for-byte (911 bytes, 334 instructions,
  eight references), including the copy's distinct `inflate_mask` table.
- Matcher corpus: the pinned `infblock.c` reproduces `inflate_blocks_reset`,
  `inflate_blocks_new`, `inflate_blocks`, and `inflate_blocks_free` at
  `0x100492c0` through `0x1004a100` byte-for-byte (3,708 bytes, 1,343
  instructions, 40 references). Its `border` and `inflate_mask` tables and all
  downstream codes/tree/flush calls are resolved to the plain-C zlib copy.
- Matcher corpus: the pinned `infcodes.c` reproduces `inflate_codes_new`,
  `inflate_codes`, and `inflate_codes_free` at `0x1004a190` through
  `0x1004a980` byte-for-byte (1,996 bytes, 692 instructions, 18 references).
- Matcher corpus: the pinned `inftrees.c` and generated `inffixed.h` reproduce
  `huft_build` and all three `inflate_trees_*` entry points at `0x1004a9a0`
  through `0x1004b0b0` byte-for-byte (1,827 bytes, 625 instructions, 18
  references). The copy's four dynamic-code tables and four prebuilt fixed-tree
  objects are named and reference-checked independently from D3DX's copy.
- Matcher corpus: the pinned `deflate.c`, `deflate.h`, `trees.c`, and generated
  `trees.h` reproduce `longest_match`, `pqdownheap`, `scan_tree`, `send_tree`,
  `compress_block`, and `bi_windup` byte-for-byte (3,411 bytes, 987
  instructions). All seven `compress_block` references resolve to the copy's
  six independently named deflate lookup tables.
- Matcher corpus: VC6 `/O2 /Ob2 /GB /W3 /MD` additionally reproduces
  `deflate_stored`, `fill_window`, `deflate_fast`, and `deflate_slow` at
  `0x100464a0` through `0x10046e70` byte-for-byte (3,532 bytes, 1,250
  instructions, 20 references). The analysis map restores the four function
  boundaries absent from Ghidra's static export and distinguishes the JAZ
  copy's `adler32` from the independent same-named executable function.
- Matcher corpus: the same profile reproduces `_tr_stored_block`,
  `_tr_flush_block`, and `build_tree` at `0x10047a30` through `0x100480f0`
  byte-for-byte (2,883 bytes, 854 instructions, 19 references). The private
  block copier, bit-length generator, and code generator are inlined exactly;
  the three newly named static tree objects resolve the remaining relocations.

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
- Matcher corpus: the pinned and provenance-checked `jdapimin.c` and
  `jdapistd.c` reproduce the eight remaining entry and local-helper bodies
  byte-for-byte (1,630 bytes, 567 instructions, 12 references). Together with
  the existing destroy wrapper, all nine exact provider functions now run
  through the normal all-scope scratch verifier.
- Matcher corpus: the adjoining JAZ error-manager cluster contributes five
  more exact callbacks (316 bytes, 132 instructions, six references). Stock
  IJG 6a source reproduces warning dispatch, formatting, and reset under VC6
  `/O2 /G6`; recovered source captures the DLL's two deliberate host-facing
  changes, returning after fatal cleanup and displaying diagnostics through a
  `JPEG Error` Win32 message box. Binary Ninja and Ghidra independently bound
  the 22-byte fatal callback that IDA omitted.
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
- Matcher corpus: the pinned upstream `jdmarker.c` reproduces eleven JAZ marker
  routines from `jpeg_resync_to_restart` through `reset_marker_reader`
  byte-for-byte (5,113 bytes, 1,819 instructions, five references). The JAZ
  Huffman allocator and natural-order table are independently named from the
  D3DX decoder copy.
- Matcher corpus: the target's VC6 `/O2 /Ob2 /G6` profile also reproduces the
  three larger `jdmarker.c` bodies byte-for-byte (1,495 bytes, 464
  instructions, 17 references): marker-reader initialization, dispatch, and
  restart handling. This completes the target's 14-function marker module;
  IJG's small SOI, DAC, and first-marker helpers are inlined into dispatch.
- Matcher corpus: the pinned upstream `jcomapi.c` reproduces the four JAZ
  common-API routines byte-for-byte (122 bytes, 48 instructions): abort,
  destroy, and both table allocators.
- Matcher corpus: five small JAZ callbacks from `jerror.c`, `jdinput.c`,
  `jdsample.c`, `jdmerge.c`, and `jquant2.c` reproduce byte-for-byte (140
  bytes, 33 instructions, seven references). The previously missing private
  `jversion.h` dependency is now pinned and provenance checked too.
- Matcher corpus: seven more `jdsample.c` functions under VC6 `/O2 /Ob2 /G6`
  plus `jcopy_sample_rows` from the newly pinned `jutils.c` reproduce
  byte-for-byte (1,848 bytes, 662 instructions, 12 references). Together with
  the three previously matched leaf adapters, this completes the target's
  ten-function separate-upsampler module.
- Matcher corpus: `jdmerge.c` under VC6 `/O2 /Ob2 /G6` reproduces all six
  separately emitted JAZ merged-upsampler bodies byte-for-byte (1,428 bytes,
  494 instructions, six references). The target inlines the YCbCr-to-RGB
  table builder into the initializer. Binary Ninja-confirmed boundaries now
  fill the five-function gap in the checked-in IDA/Ghidra exports with bounded
  curated entries.
- Matcher corpus: the newly pinned and provenance-checked `jdcolor.c` under
  VC6 `/O2 /Ob2 /G6` reproduces all six separately emitted JAZ color
  deconverter bodies byte-for-byte (1,424 bytes, 476 instructions, 11
  references). Its empty `start_pass_dcolor` callback is linker-folded with
  the existing one-byte memory-source terminator; live-confirmed bounds fill
  the corresponding six-function static-export gap.
- Matcher corpus: the newly pinned and provenance-checked `jdmaster.c` under
  VC6 `/O2 /Ob2 /G6` reproduces all five emitted JAZ decompression-master
  bodies byte-for-byte (1,679 bytes, 570 instructions, 25 references). The
  private range-table and module-selection routines are inlined into the
  initializer; explicit live-confirmed bounds cover the previously unnamed
  dimension, merged-upsample, prepare-pass, and finish-pass routines.
- Matcher corpus: the newly pinned `jdmainct.c`, `jmemnobs.c`, and private
  `jmemsys.h` dependency are provenance checked. Under VC6 `/O2 /Ob2 /G6`,
  all five emitted main-buffer-controller bodies match byte-for-byte (1,710
  bytes, 578 instructions, four references), as do the three adjacent
  no-backing-store hooks (28 bytes, 12 instructions). The empty memory
  terminator is linker-folded with the existing one-byte callback.
- Matcher corpus: the newly pinned and provenance-checked `jdcoefct.c` under
  VC6 `/O2 /Ob2 /G6` reproduces all eight emitted JAZ coefficient-controller
  bodies byte-for-byte (4,104 bytes, 1,322 instructions, 12 references). The
  private `start_iMCU_row` and `smoothing_ok` helpers are inlined into their
  callers, so no synthetic target functions are recorded for them.
- Matcher corpus: the same official `jdcoefct.c` reproduces five D3DX bodies
  under `/O1 /G6`: full-buffer and single-pass output, full-buffer and dummy
  input consumption, and controller initialization (1,498 bytes, 503
  instructions, 11 references). Live Binary Ninja boundaries recover the
  three previously unnamed local bodies. The independently linked provider
  retains its own coefficient-controller state and function identity; its
  progressive smoothed-output loop remains an honest stock-source residual.
- Matcher corpus: the newly pinned and provenance-checked `jmemmgr.c`
  reproduces seventeen memory-manager bodies across the D3DX and JAZ copies
  (3,328 bytes, 1,380 instructions, 34 references). Ten D3DX bodies use the
  provider's `/O1 /G6` code-generation profiles; seven JAZ request,
  realization, access, and backing-store bodies use `/O2 /G6`. The two D3DX
  accessors remain honest one-instruction compiler/source residuals rather
  than being shaped to force byte identity.
- Matcher corpus: the newly pinned `jdhuff.c` and private `jdhuff.h` dependency
  are provenance checked. Under VC6 `/O2 /Ob2 /G6`, all six separately
  emitted baseline Huffman-decoder bodies reproduce byte-for-byte (2,528
  bytes, 857 instructions, 20 references). The private `process_restart`
  helper is inlined into `decode_mcu`, and its two sign-extension tables now
  have explicit reference identities rather than anonymous data addresses.
- Matcher corpus: `jdphuff.c` under the same VC6 `/O2 /Ob2 /G6` profile
  reproduces all six emitted progressive Huffman-decoder bodies byte-for-byte
  (3,788 bytes, 1,230 instructions, 31 references). Its private
  `process_restart` helper is likewise inlined, and the module-local
  sign-extension tables are explicitly separated from the baseline copies.
- Matcher corpus: `jddctmgr.c` under VC6 `/O2 /Ob2 /G6` reproduces both
  emitted inverse-DCT manager bodies byte-for-byte (654 bytes, 211
  instructions, 14 references). The manager's two AA&N scale tables and all
  six selected JAZ IDCT implementations now have stable reference identities;
  this naming does not by itself claim the downstream IDCT bodies are exact.
- Matcher corpus: the newly pinned `jidctfst.c` and `jidctint.c` complete the
  official JAZ inverse-DCT source set. Under VC6 `/O2 /Ob2 /G6`, the
  fast-integer, floating-point, and one-pixel transforms reproduce byte-for-byte
  (2,349 bytes, 673 instructions, 18 references); the floating constants have
  explicit identities, and live bounds restore the previously omitted
  one-pixel function. The slow-integer, 4-by-4, and 2-by-2 transforms are
  semantic-complete compiler residuals across the full installed compiler and
  profile matrix, without matcher-only source shaping.
- Matcher corpus: `jdpostct.c` under VC6 `/O2 /Ob2 /G6` reproduces all five
  emitted decompression-postprocessor bodies byte-for-byte (829 bytes, 312
  instructions, five references). Live-confirmed boundaries fill the static
  export gaps for the pass selector and one-pass processing callback; the
  unreferenced alignment thunk immediately before the initializer is omitted.
- Matcher corpus: `jdinput.c` under the target's VC6 `/O2 /Ob2 /G6` profile
  reproduces the remaining five JAZ input-controller functions byte-for-byte
  (2,157 bytes, 672 instructions, 15 references). Together with
  `finish_input_pass`, the complete six-function input-controller cluster is
  now exact; the `/Ob2` profile accounts for IJG's inlined setup helpers.
- Matcher corpus: `jquant2.c` under the same VC6 `/O2 /Ob2 /G6` profile
  reproduces eleven additional JAZ two-pass quantizer functions byte-for-byte
  (4,883 bytes, 1,659 instructions, 18 references). Together with the already
  matched color-map callback, this completes every separately emitted target
  body from the module; the empty `finish_pass2` callback is linker-folded
  with the existing one-byte memory-source terminator.
- Matcher corpus: the newly pinned and provenance-checked `jquant1.c`
  reproduces eight separately emitted JAZ one-pass quantizer bodies
  byte-for-byte (1,977 bytes, 690 instructions, three references). The stock
  VC6 surrogate needs `/O2 /G6` to retain the independently emitted
  `select_ncolors` body and `/O2 /Ob2 /G6` for the other seven exact bodies.
  Colormap construction and the ordered/Floyd-Steinberg setup helpers are
  inlined. The initializer retains an explicit compiler-only over-inlining
  residual, while the pass initializer differs only in one independent-load
  scheduling swap; both remain semantic-complete without source shaping.
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
- Evidence: Grim functions including `grim_app_pump` at `0x10003090` call
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
