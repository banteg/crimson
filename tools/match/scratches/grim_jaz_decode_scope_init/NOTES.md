# grim_jaz_decode_scope_init

Native target: `grim.dll` at `0x1000a810..0x1000a813` (3 bytes).

The empty `GrimJazDecodeScope` constructor returns `this` in `eax`. Its only
known callsite constructs the helper immediately before
`grim_jaz_decompress_payload` in `grim_decode_jaz_texture`.

The VC6 `/O2 /GB /GX /MD` constructor is an exact 2-instruction match.
