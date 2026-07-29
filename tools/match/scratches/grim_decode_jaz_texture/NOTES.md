# grim_decode_jaz_texture

Native target: `grim.dll` at `0x10004b70..0x10004e81` (785 bytes).

Exact Microsoft Visual C++ 6.5 `/O2 /GB /W3 /GR- /GX /MD` match:
**252/252 normalized instructions**, all **785/785 fuzzy-weighted bytes**, and
all **22 references** resolve (`22/0/0`).

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
- A one-pass `do/while (0)` region expresses the native failure lifetime
  without an explicit label. The null-payload and allocation failures break
  out of that region, while the setjmp handler retains a direct `return 0` and
  success returns the decoded image. This asymmetric ordinary source is
  material: making all three failures break is similar but not exact.
- Width is published first, the image cursor is advanced past the TGA header,
  and height is then published. Staging
  `output_width * output_components` in the natural `row_samples` local before
  the `alloc_sarray` call produces the native register schedule. Each change
  alone regresses; their interaction is exact.

## Exact reference audit

The final instruction match initially left four masked relocations unresolved.
They are now tied to live native evidence rather than ignored:

- VC6 local `$L519` is the compiler-generated exception-handler thunk at
  `0x1004b7e8`. It loads `0x100516e8` and tail-jumps to
  `__CxxFrameHandler`.
- VC6 local `$T507` is the corresponding C++ `FuncInfo` record at
  `0x100516e8`, beginning with the VC6 magic `0x19930520`. It is referenced by
  both the handler thunk and the decode function's setjmp setup.
- Binary Ninja resolves the cleanup calls at `0x10004cb5` and `0x10004e69` to
  the one-byte `grim_noop` at `0x10001160`; both callsites first load the scope
  address into `ecx` and mark the C++ unwind state complete. The same native
  address is also called as the variadic disabled-log sink throughout the
  platform code. This is evidence for linker-folded
  `_grim_noop`/`GrimJazDecodeScope::~GrimJazDecodeScope` aliases, not grounds
  to rename the canonical noop or add a fake destructor stub. The native-link
  track now records both callsites in
  `tools/native/linker_aliases/grim.dll.json`, verifies their direct targets
  against the pinned DLL, and emits the corresponding COFF weak alias.

`scratch.conf` scopes those three compiler-local identities through
`REFERENCE_ALIASES`. The curated EH-handler name and annotation-only FuncInfo
anchor live in `analysis/ghidra/maps/name_map.json` and `data_map.json`; the
FuncInfo anchor is excluded from port-owned native data closure. With those
aliases the matcher audits `22/0/0` references and reports a true exact match.

## Same-TU destructor falsification

The historical recorded `same-tu-empty-destructor` probe was byte-neutral
against the original 86.51% early-return source. The current
`same-tu-destructor-mutations.json` replay is stronger: defining the empty
destructor beside the exact source falls to **88.67%**, produces 251 rather
than 252 instructions, shortens the exact prefix to 16, and leaves references
at `20/2/0`.

The missing source-level destructor definition is therefore not the body or
audit fix. The evidence-backed weak alias to the folded native `grim_noop`
remains the correct link model; expanding the JAZ cluster solely to supply
that destructor would regress the exact function.

## Recorded shared-failure sweep

Live native disassembly shows the null-payload, setjmp, and allocation
failures converging on the scope-cleanup return block at `0x10004cab`.

`shared-failure-epilogue-mutations.json` records the corresponding explicit
source shape. Merely naming the final label, or routing either one failure to
it, compiles byte-identically at 86.51%. Routing both failures through the
shared label remains at 252 instructions but shortens the exact prefix to 11
instructions and falls to 82.14%. Incomplete dependent combinations fail to
compile because the label is absent.

`one-pass-failure-flow-mutations.json` records the decisive 15-combination
structured sweep. Starting from 86.51%, routing null payload and allocation
failure through the one-pass breaks while leaving the setjmp return unchanged
raises the function to **98.02%**, moves the prefix from 32 to 107
instructions, and leaves only a five-instruction publication schedule.
Changing the setjmp exit to a break as well reaches only 93.25%; the
asymmetry is causal rather than cosmetic.

## Exact scheduling interaction

At 98.02%, direct permutations and isolated allocation spellings could not
close the last region. `publication-allocation-interactions-mutations.json`
then evaluates all 15 singles and pairs between the native-looking
width/image/height publication order and seven ordinary allocator-expression
shapes.

The unique winner combines width/image/height publication with a
`row_samples` local. It adds the remaining `15.58` fuzzy-weighted bytes,
extends the exact prefix from 107 to all 252 instructions, and reaches
**100.00% with no tradeoff**. The nearest alternatives retain a 9.35-byte
residual. This is useful interaction evidence: both winning source boundaries
regress in isolation, so neither would have been retained by a single-site
sweep.

Additional recorded wrapper, declaration-lifetime, output-order, allocator,
and same-TU destructor sweeps bound the nearby alternatives. No inline
assembly, volatile state, dummy reference, forced address, register hint, or
layout-only arithmetic is used. All decode, cleanup, exception, header,
scanline, and alpha-RLE behavior is represented by ordinary C++ and the
scratch is exact.
