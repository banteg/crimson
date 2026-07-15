# `effect_pool_vertices_global_init`

Native target: `crimsonland.exe` at `0x0042de10` (39 bytes).

The global initializer walks all 512 effect entries at their 0xbc-byte stride
and invokes the recovered no-op constructor over each four-vertex, 0x1c-stride
quad. The callback address is shared with the equivalent UI vertex type.
All 15 instructions and all three static references match exactly.
