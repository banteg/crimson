# Scratch Headers

Put shared matching-only C/C++ declarations here when multiple scratches need
the same recovered layout. The compiler wrapper also adds
`third_party/headers` to `INCLUDE`.

`crimsonland_textures_owner.h` restores the authenticated 2003 `textures_t`
aggregate over the recovered 1.9.93 texture-handle globals.  Consumers opt in
to the original member ownership only after their legacy extern declarations,
so the same header can also provide explicit `texture_handles.*` access where
that is clearer.

`crimsonland_gfxs_owner.h` does the same for the twelve contiguous `gfx_t`
objects in the original `gfxs_t`.  A scratch can override
`CRIMSONLAND_GFX_BLOCK_TYPE` when its exact constructor-facing class view is
more specific than the shared recovered block type.

`crimsonland_terrain_owner.h` restores the authenticated 2003 `terrain_t`
aggregate rooted at `terrain_render_target`: the render target, dimensions,
three selectors, and sixteen terrain texture handles.  Exact producer and
consumer calibrations guard the recovered member offsets before WIP scratches
opt in to the aggregate names.

`crimsonland_config_owner.h` restores the authenticated 1.9.93 `config_t`
owner rooted at `config_blob`.  Its opt-in aliases replace the independently
recovered game-mode, hardcore, and violence-disable symbols with their proven
interior members without changing the compiler-facing layout.
