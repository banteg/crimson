# Grim decoder callbacks

The image-decoder cluster contributes nine exact callback leaves across its
JPEG, PNG, and zlib paths.

The D3DX JPEG memory source shares a no-op for `init_source` and `term_source`.
Its refill callback restores `next_input_byte` and `bytes_in_buffer` from the
two private fields at offsets `0x1c` and `0x20`; its skip callback advances and
shrinks that same window. This is distinct from the separately linked JAZ
decoder's buffered IJG source manager.

The PNG path supplies a longjmp error callback, two free adapters, and a
64-byte info-structure clear. The clear requires the evidenced `/Oi` intrinsic
profile to emit the native `rep stosd`. The two free adapters require the VC6
Processor Pack profile: its optimizer emits the native direct tail jumps,
where stock VC6 emits call/cleanup/return sequences for the same source.

The zlib allocation callbacks ignore their opaque argument and forward to
`calloc(item_count, item_size)` and `free(allocation)`. VC6 `/O1 /G6` emits
both wrappers exactly. Altogether the nine functions cover 109 bytes and 41
instructions in the explicit `all` scope, with every external relocation
resolved.
