# grim_release_geometry_buffers

`grim_release_geometry_buffers` at `0x100044e0` independently releases the
dynamic vertex and index buffers and clears both globals unconditionally. The
unconditional stores matter: they let VC6 schedule the index-buffer load before
clearing the vertex-buffer global, matching the native instruction order.

The recovered helper matches all 15 instructions and all four references under
MSVC 6.5 `/O2 /GB`.
