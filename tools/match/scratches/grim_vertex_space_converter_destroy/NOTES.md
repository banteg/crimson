# `grim_vertex_space_converter_destroy`

Native target: `grim.dll` at `0x1001692e` (19 bytes).

The virtual destructor restores the converter's own vtable and releases its
owned converted-vertex buffer at offset `0x104c` with scalar `operator delete`.
