# `unused_effect_uv16_prefix_vec2_global_init`

Exact 21-byte, three-instruction match with both data references proven. It
zeroes the two-word C++ startup object at `0x004aa4d0`, immediately before the
`effect_uv16` table. No runtime code references either word, so the name keeps
the object's unused/prefix status explicit; `vec2` records the two-float
adjacent layout without assigning a gameplay role.
