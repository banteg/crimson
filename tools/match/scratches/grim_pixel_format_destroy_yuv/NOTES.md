# `grim_pixel_format_destroy_yuv`

Native target: `grim.dll` at `0x1001b493` (73 bytes).

The virtual destructor flushes any dirty packed YUV cache, releases the
16-byte-entry cache array at offset `0x106c`, and then lets the common pixel
format/converter base destructor release its converted-vertex buffer.

The local-label alias identifies the compiler-generated EH handler emitted by
this destructor; it does not add a source-level call or constrain codegen.
