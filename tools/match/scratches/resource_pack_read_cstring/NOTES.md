# resource_pack_read_cstring

Reads a NUL-terminated entry name into the shared 512-byte pack-name buffer and
returns whether EOF remained clear. The native loop has no destination bound.

Exact 24/24-instruction match with all three native references aligned.
