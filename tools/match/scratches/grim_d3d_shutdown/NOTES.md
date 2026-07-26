# grim_d3d_shutdown

`grim_d3d_shutdown` at `0x10004280` now has a complete plausible teardown
shape:

- release and clear the cached backbuffer/render-target surfaces when their
  COM reference counts reach zero;
- do the same for the embedded font and splash textures;
- delete and clear all 256 owned `GrimTexture` slots;
- call the exact-matched `grim_release_geometry_buffers` helper;
- release and unconditionally clear the D3D device and Direct3D8 interface.

The candidate has the same 72 instructions and all 15 references, with an
exact 40-instruction prefix. The remaining normalized diff is confined to the
texture-slot loop: VC6 assigns the induction pointer and temporary texture to
`ESI`/`EDI`, while the native assigns them to `EDI`/`ESI`. The loop topology,
destructor/delete calls, signed 256-entry bound, stores, and surrounding code
are otherwise identical. Register-forcing constructs were not introduced, so
this remains honestly marked WIP.
