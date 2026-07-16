# `grim_pixel_format_init_yuv`

Native target: `grim.dll` at `0x1001a444` (248 bytes).

This shared UYVY/YUY2 base constructor aligns the horizontal cache interval to
two pixels, allocates an array of 16-byte channel entries, disables the cache
on allocation failure, and selects the packed chroma/luma byte offsets from
the descriptor FourCC. The `new[]` expression explains the native VC6 EH and
vector-constructor machinery without spelling those helpers by hand.

The reference aliases identify the compiler-generated local EH handler, VC6 EH
prologue, and vector-constructor iterator emitted by this natural `new[]` source;
they do not introduce external calls or constrain instruction selection.
