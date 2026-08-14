# Scratch Headers

Put shared matching-only C/C++ declarations here when multiple scratches need
the same recovered layout. The compiler wrapper also adds
`third_party/headers` to `INCLUDE`.

`crimsonland_textures_owner.h` restores the authenticated 2003 `textures_t`
aggregate over the recovered 1.9.93 texture-handle globals.  Consumers opt in
to the original member ownership only after their legacy extern declarations,
so the same header can also provide explicit `texture_handles.*` access where
that is clearer.
