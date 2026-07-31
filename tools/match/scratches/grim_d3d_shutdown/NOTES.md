# grim_d3d_shutdown

`grim_d3d_shutdown` at `0x10004280` is exact under the pinned VC6.5 profile.
The recovered teardown:

- release and clear the cached backbuffer/render-target surfaces when their
  COM reference counts reach zero;
- do the same for the embedded font and splash textures;
- delete and clear each non-null owned `GrimTexture` slot across the 256-entry
  table;
- call the exact-matched `grim_release_geometry_buffers` helper;
- release and unconditionally clear the D3D device and Direct3D8 interface.

The decisive source-shape evidence was the texture loop's explicit null guard
and direct `grim_texture_slots[i]` delete. That natural form makes VC6 select
the native `EDI` induction cursor and `ESI` texture temporary; caching the
texture in a source local instead inverted those registers. The final
candidate is exact at 196/196 bytes and 72/72 instructions with all 17
references resolved.
