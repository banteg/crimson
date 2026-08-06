# Grim decoder callbacks

The image-decoder cluster contributes ninety-six exact callback, state, and cleanup
leaves across its JPEG, PNG, and zlib paths.

The D3DX JPEG memory source shares a no-op for `init_source` and `term_source`.
Its refill callback restores `next_input_byte` and `bytes_in_buffer` from the
two private fields at offsets `0x1c` and `0x20`; its skip callback advances and
shrinks that same window. This is distinct from the separately linked JAZ
decoder's buffered IJG source manager.

The D3DX IJG error-manager reset clears the accumulated warning count and
message code. The pinned DirectX archive uniquely identifies the exact
`jerror.obj` member and symbol.

The rest of that `jerror.obj` member now recovers the fatal-error path,
warning/trace dispatch, diagnostic formatting, output sink, and standard
error-manager initializer. The D3DX output sink intentionally formats into a
200-byte local buffer without printing it. The fatal path preserves the
compiler-emitted unreachable `pop esi` after `exit`; an explicit scratch end
includes that provider-confirmed byte when the imported function boundary
stops at the noreturn call. The initializer binds all five callbacks plus the
existing reset helper and the archive-confirmed 120-entry message table.

Three additional IJG leaves recover ceiling division, divisor rounding, and
the input-pass transition back to `consume_markers`. Their exact archive
symbols come from `jutils.obj` and `jdinput.obj`.

The PNG path supplies a longjmp error callback, `png_zfree` and
`png_destroy_struct` adapters, a warning dispatcher, `png_info_destroy`, and
CRC reset/update helpers. The pinned DirectX 8.1 archive identifies the exact
members and symbols and stamps each object with `@comp.id=0x001d23da`
(product 29, build 9178). The locally available MSVC 7 profile reproduces the
two native tail jumps exactly and is retained as a compatible code-generation
surrogate, not as original-compiler provenance. Stock VC6 reproduces the other
helpers exactly; `png_info_destroy` additionally requires `/Oi` to emit its
native `rep stosd`. The CRC update preserves libpng's distinct ancillary and
critical-chunk ignore policies.

The same archive uniquely identifies the PNG error callback configuration,
read dispatch, read callback configuration, and signature comparison helpers.
The read-dispatch extent is curated through `0x100204a4`, restoring the native
caller cleanup and return that the imported IDA boundary omitted. The signature
comparison's global reference is bound to the archive-confirmed eight-byte PNG
signature at `0x1004e51c`.

The PNG leaf group also includes validity, row-byte, and channel getters plus
the BGR, 16-bit swap, packed-sample, and Adam7 setup helpers. These preserve the
libpng 1.0.5 structure offsets and flag values identified by the matching
`pngget.obj` and `pngtrans.obj` members.

The matching `pngget.obj` and `pngset.obj` members additionally recover the
gAMA, sRGB, and PLTE metadata getters and setters. The default `png_free`
helper dispatches to the CRT only when both its libpng context and allocation
are present. The D3DX-linked IJG common helpers destroy decoder state and
allocate initialized quantization and Huffman tables. The pinned provider
objects retain product 29, build 9178 provenance; stock VC6 `/O1 /G6` is an
exact local code-generation surrogate for the two table allocators, not a
claim about their original compiler.

Ten more helpers are reconstructed from the official libpng 1.0.5 source at
tag `v1.0.5` and checked against the pinned archive: whole-image and info
updates, filler and gamma setup, 16-bit swap and chop transforms, the zlib
allocator, info allocation, and the checked copy/fill wrappers. The provider's
feature selection gives its info structure a 0x40-byte initialized extent.
`/Oi` reproduces its intrinsic `fabs`, `memcpy`, and `memset` expansions; that
flag is retained only on the five scratches whose exact bodies require it.
These provider objects also carry product 29, build 9178 provenance; the local
`msvc7.0` profile is an exact code-generation surrogate rather than an
original-compiler claim.

The source/archive overlap further recovers the compound sRGB/gamma and tRNS
setters, internal structure allocation, big-endian integer load, CRC read,
comparison and finish helpers, chunk-name validation, and the IEND and unknown
chunk handlers. The provider feature set omits cHRM work from the compound
setter and uses 0x19c-byte PNG and 0x40-byte info structures. Only
`png_create_struct` selects `/MT`, matching its archive object's direct
`malloc` relocation; the other utility scratches retain `/MD`.

The archive-confirmed post-transform info updater and row initializer add the
provider's larger read-side setup bodies. The info updater retains expand,
gamma, 16-to-8, dither, pack, and filler handling. The row initializer retains
Adam7, pack, expand, and filler sizing, then allocates and clears the two row
buffers through the provider helpers. Its dynamic Adam7 width calculation is
bound to the exact seven-entry `png_pass_start` and `png_pass_inc` tables. The
local `msvc7.0` profile reproduces both bodies exactly as a code-generation
surrogate for their product 29, build 9178 archive objects.

Ten IJG 6a routines are reconstructed directly from the official source and
their uniquely matching DirectX archive symbols: marker and input-controller
resets, input-controller allocation, sample and coefficient-row copies,
far-buffer zeroing, out-of-memory dispatch, memory-manager teardown, operation
abort, and output-pass completion. The archived private error helper uses an
EAX/EDX translation-unit calling convention, so the matcher source retains one
ordinary local call site to reproduce it without changing the recovered body.
The available `msvc7.0` profile emits eight routines exactly. Its scheduling of
the two input-controller state stores differs from build 9178, while the
already-supported `msvc6.5` D3DX JPEG surrogate emits those same recovered
sources exactly; neither local profile is claimed as the original compiler.

Nine more official IJG 6a leaves recover the no-backing-store memory policy,
separate and merged upsampler pass setup, full-size and ignored-component
adapters, grayscale row conversion, and both quantizer colormap callbacks.
Their symbols are unique within the pinned `jmemnobs.obj`, `jdsample.obj`,
`jdcolor.obj`, `jdmerge.obj`, `jquant1.obj`, and `jquant2.obj` members. The
local `msvc7.0` profile reproduces eight bodies exactly; the already-supported
`msvc6.5` surrogate reproduces the merged-upsample Boolean-clear instruction
shape. Both remain code-generation surrogates for product 29, build 9178.

The separately linked JAZ decoder copy contributes seven byte-identical IJG
helpers: the two integer rounders, coefficient-row copy, far-buffer clear,
memory availability policy, and two upsampler leaves. Unique archive symbols
anchor each target identity. The two bulk-memory helpers retain `/Oi` so the
local compiler emits the native inline `rep` sequences.

Four additional D3DX processing leaves recover the two-pass postprocessor
dispatch, coefficient input-pass reset, one-row merged upsampler, and
first-pass quantizer finalizer. The coefficient initializer preserves the
archive-local fastcall tail jump. The quantizer object passes its decoder in
`EDI` to the archive-local `select_colors`; the matcher source retains that
official IJG routine as a translation-unit callsite so MSVC reproduces the
same internal convention, while only the finalizer is claimed exact here.

Three more IJG 6a helpers recover the coefficient controller's per-row state,
the common horizontal two-to-one upsampler, and Floyd-Steinberg error-buffer
allocation. The row initializer preserves the archive-local fastcall entry;
the allocator is retained behind a translation-unit callsite so MSVC selects
the same decoder-in-`ESI` internal convention as the pinned archive member.

The next three exact leaves cover progressive smoothing eligibility, the
coefficient controller's output-pass selection, and horizontal-plus-vertical
two-to-one upsampling. Keeping the official `smoothing_ok` body in the shared
translation unit reproduces its decoder-in-`ESI` internal convention and the
caller's three archive-local references without artificial assembly shaping.

Three exact upsampling bodies complete the integral-ratio box filter and both
triangle-filter variants for the common two-to-one sampling cases. Their
component and upsampler layouts expose only archive-backed fields, including
the byte-sized expansion tables and the component's downsampled width.

The zlib allocation callbacks ignore their opaque argument and forward to
`calloc(item_count, item_size)` and `free(allocation)`. Its inflate-codes
cleanup dispatches the configured free callback with the stream's opaque
value. VC6 `/O1 /G6` emits all three wrappers exactly. The JPEG destroy wrapper
uses its library's `/O2` profile and forwards to the common destroy routine.

Altogether the one hundred five functions cover 5,385 bytes and 2,032 instructions in the
explicit `all` scope, with every external relocation resolved.
