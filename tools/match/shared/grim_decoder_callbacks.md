# Grim decoder callbacks

The image-decoder cluster contributes fourteen exact callback and cleanup
leaves across its JPEG, PNG, and zlib paths.

The D3DX JPEG memory source shares a no-op for `init_source` and `term_source`.
Its refill callback restores `next_input_byte` and `bytes_in_buffer` from the
two private fields at offsets `0x1c` and `0x20`; its skip callback advances and
shrinks that same window. This is distinct from the separately linked JAZ
decoder's buffered IJG source manager.

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

The zlib allocation callbacks ignore their opaque argument and forward to
`calloc(item_count, item_size)` and `free(allocation)`. Its inflate-codes
cleanup dispatches the configured free callback with the stream's opaque
value. VC6 `/O1 /G6` emits all three wrappers exactly. The JPEG destroy wrapper
uses its library's `/O2` profile and forwards to the common destroy routine.

Altogether the fourteen functions cover 246 bytes and 93 instructions in the
explicit `all` scope, with every external relocation resolved.
