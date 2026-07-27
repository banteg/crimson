# grim_decode_jaz_texture

Native target: `grim.dll` at `0x10004b70..0x10004e81` (785 bytes).

This is an evidence-backed semantic-complete reconstruction, not an exact
match. Microsoft Visual C++ 6.5 with `/O2 /GB /W3 /GR- /GX /MD` produces 252
normalized instructions, the same count as the native function, with a
32-instruction prefix, 86.51% similarity, and masked references `18/3/0`.

## Recovered source shape

- The function has five cdecl arguments: source pointer, unused source size,
  output image size, output width, and output height. The fifth argument is
  established by the native `[ebp+0x18]` accesses and caller stack setup.
- A small C++ scope object calls the JAZ unpacker before decoding. The unpacked
  payload begins with a little-endian JPEG byte count followed by JPEG data;
  alpha RLE begins immediately after that JPEG segment.
- The scope constructor, zlib status classifier, allocation/decompression
  method, and version-1 envelope unpacker are independently exact-matched at
  `0x1000a810..0x1000a8c2`. They are Grim-owned helpers immediately before the
  VC6 runtime/import seam, not part of the linked D3DX archive.
- The native libjpeg ABI is version 61. `jpeg_decompress_struct` occupies
  `0x1a8` bytes and the custom error object combines a `0xc4`-byte error
  manager with a 64-byte `jmp_buf`. `setjmp` protects the complete JPEG decode
  and the custom `error_exit` longjmps back into this function.
- The helpers at `0x1003ab10` and `0x1003a990` are now identified as
  `jpeg_std_error` and the D3DX8 in-memory source adapter
  `grim_jpeg_memory_src`. The former installs the standard five IJG error
  callbacks and version-6a message table; the latter allocates and initializes
  a `jpeg_source_mgr` with the supplied buffer and size. Naming them resolves
  two previously unknown call references without changing source code.
- The decoder allocates an 18-byte TGA header plus one 32-bit pixel per output
  sample. JPEG RGB rows are copied bottom-up into BGRA pixels with alpha 255.
  A zero-width guard around a `do/while` reproduces the native single pre-test,
  pointer walk, and unsigned backedge.
- The packed TGA header uses one four-byte zero write for the color-map origin
  and length fields, followed by zero color-map depth, zero origins, 16-bit
  dimensions, 32 bits per pixel, and descriptor 8.
- Alpha is decoded as `(run_length, value)` byte pairs from the unpacked JAZ
  tail and written bottom-up. The native retry shape decrements the horizontal
  coordinate when loading a fresh run so that the same pixel is revisited.
- The unpacked buffer is released only on the successful tail. The input-size
  argument is unused, and native code dereferences the unpack result before a
  meaningful null check; the scratch preserves those observed weaknesses.

## Remaining mismatch

The semantic body and scanline loop are recovered, but VC6 lays out two
equivalent regions differently from the native function:

- Natural early returns emit the C++ scope-destructor failure epilogue beside
  each error path, while the native binary shares one failure epilogue between
  the setjmp, allocation, and empty-payload branches. Nested, `goto`, and
  single-exit spellings were tested; they either retained the block-placement
  difference or changed real local lifetimes and degraded the match.
- Independent width/height stores and the image-header pointer adjustment use
  a different register schedule immediately before `alloc_sarray`.
- Binary Ninja resolves the cleanup calls at `0x10004cb5` and `0x10004e69` to
  the one-byte `grim_noop` at `0x10001160`; both callsites first load the scope
  address into `ecx` and mark the C++ unwind state complete. The same native
  address is also called as the variadic disabled-log sink throughout the
  platform code. This is evidence for linker-folded
  `_grim_noop`/`GrimJazDecodeScope::~GrimJazDecodeScope` aliases, not grounds
  to rename the canonical noop or add a fake destructor stub. The native-link
  track must provide an explicit evidence-backed alias.

No inline assembly, volatile state, dummy reference, forced address, or
layout-only arithmetic is used. The three remaining unresolved references are
compiler-private exception or stack-local labels rather than unidentified
external functions or data. All observed decode, cleanup, header, and alpha-RLE
behavior is represented; the remaining shared-epilogue placement and register
schedule are compiler-shape debt, so the scratch is classified
semantic-complete with a compiler residual.
