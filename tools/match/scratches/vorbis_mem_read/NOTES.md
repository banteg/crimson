# vorbis_mem_read

Native target: `crimsonland.exe` at `0x0041dce0` (88 bytes).

The Vorbis read callback treats its datasource as the inline bytes following
an eight-byte size/cursor prefix. It resets a cursor at or beyond the source,
copies at most the remaining bytes, but advances by the full requested
`size * count` rather than the truncated copy count.

The source deliberately leaves the repeated `size * count` expressions in
their natural callback form. VC6 common-subexpression elimination keeps one
requested-byte value and emits the native register/SIB schedule. The separate
size and cursor prefix pointers preserve their real aliasing. The result
matches all 37 instructions with no reference debt.
