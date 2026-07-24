# resource_pack_read_cstring

Reads a NUL-terminated entry name into the shared 512-byte pack-name buffer and
returns whether EOF remained clear. The native loop has no destination bound.

Exact 24/24-instruction match with all three native references aligned.

The stream parameter now uses the recovered 0x20-byte MSVC 6 `_iobuf` layout.
Both EOF tests are direct reads of `FILE::_flag & 0x10`; Binary Ninja no longer
needs to render the game-owned loop through an opaque `fp+0x0c` access.
