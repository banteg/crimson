# Grim decoder callbacks

The image-decoder cluster contributes fourteen exact callback and cleanup
leaves across its JPEG, PNG, and zlib paths.

The D3DX JPEG memory source shares a no-op for `init_source` and `term_source`.
Its refill callback restores `next_input_byte` and `bytes_in_buffer` from the
two private fields at offsets `0x1c` and `0x20`; its skip callback advances and
shrinks that same window. This is distinct from the separately linked JAZ
decoder's buffered IJG source manager.

The PNG path supplies a longjmp error callback, two free adapters, a warning
dispatcher, a 64-byte info-structure clear, and CRC reset/update helpers. The
clear requires the evidenced `/Oi` intrinsic profile to emit the native
`rep stosd`. The two free adapters require the VC6 Processor Pack profile: its
optimizer emits the native direct tail jumps, where stock VC6 emits
call/cleanup/return sequences for the same source. The CRC update preserves
libpng's distinct ancillary and critical-chunk ignore policies.

The zlib allocation callbacks ignore their opaque argument and forward to
`calloc(item_count, item_size)` and `free(allocation)`. Its inflate-codes
cleanup dispatches the configured free callback with the stream's opaque
value. VC6 `/O1 /G6` emits all three wrappers exactly. The JPEG destroy wrapper
uses its library's `/O2` profile and forwards to the common destroy routine.

Altogether the fourteen functions cover 246 bytes and 93 instructions in the
explicit `all` scope, with every external relocation resolved.
