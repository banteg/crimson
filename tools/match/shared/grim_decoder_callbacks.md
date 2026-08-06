# Grim decoder callbacks

The image-decoder cluster contributes forty-nine exact callback, state, and cleanup
leaves across its JPEG, PNG, and zlib paths.

The D3DX JPEG memory source shares a no-op for `init_source` and `term_source`.
Its refill callback restores `next_input_byte` and `bytes_in_buffer` from the
two private fields at offsets `0x1c` and `0x20`; its skip callback advances and
shrinks that same window. This is distinct from the separately linked JAZ
decoder's buffered IJG source manager.

The D3DX IJG error-manager reset clears the accumulated warning count and
message code. The pinned DirectX archive uniquely identifies the exact
`jerror.obj` member and symbol.

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

The zlib allocation callbacks ignore their opaque argument and forward to
`calloc(item_count, item_size)` and `free(allocation)`. Its inflate-codes
cleanup dispatches the configured free callback with the stream's opaque
value. VC6 `/O1 /G6` emits all three wrappers exactly. The JPEG destroy wrapper
uses its library's `/O2` profile and forwards to the common destroy routine.

Altogether the forty-nine functions cover 1,559 bytes and 589 instructions in the
explicit `all` scope, with every external relocation resolved.
