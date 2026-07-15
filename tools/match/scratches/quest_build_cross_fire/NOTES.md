# `quest_build_cross_fire`

Native target: `crimsonland.exe` at `0x00435480` (390 bytes).

Live Binary Ninja evidence recovers seven fixed entries. Template `0x40`
spiders appear at `(1074, height * 0.5)` at 100 ms and at `(512, 1152)` and
`(512, -128)` at 26000 ms, all count six. Template `0x3c` spiders appear at
`(-40, 512)` at 5500/count four and 15500/count six, then at `(-100, 512)`
at 25500/count eight. A template `0x01` splitter occupies `(512, 512)` at
18500 ms/count two. The lower `(512, 1152)` coordinate is a hard-coded native
constant, not a map-size-derived bottom edge.

Whole-vector construction reproduces the native reusable eight-byte temporary,
the height-to-x87 conversion, shared registers for 512, template `0x3c`,
template `0x40`, trigger 26000, and count six, plus the exact entry offsets and
epilogue. The candidate has the same 76 instructions, preserves a ten-
instruction prefix, both references, and scores 81.58%.

The residual is independent VC6 scheduling across adjacent fixed entries:
native overlaps each following vector temporary with the preceding metadata,
whereas the candidate completes several position stores earlier. A two-field
metadata setter with explicit count and direct first-entry metadata produce the
same or worse schedule; `msvc6.5pp` is identical. The exact-length
default-profile form is retained without artificial dependencies or register
forcing.
