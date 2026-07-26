# grim_create_geometry_buffers

`grim_create_geometry_buffers` at `0x10004350` allocates the dynamic vertex and index buffers,
fills the index buffer with two triangles for each four-vertex quad, and binds
both buffers to the Direct3D8 device.

The buffers hold 256 vertices with a 28-byte stride and 12 index bytes per
quad-sized four-vertex group. The index sequence is `(0,1,2, 2,3,0)` for each
group, advanced in steps of four.

The recovered function matches all 107 native instructions and all 32 masked
references across its 387-byte body under MSVC 6.5 `/O2 /GB`.
