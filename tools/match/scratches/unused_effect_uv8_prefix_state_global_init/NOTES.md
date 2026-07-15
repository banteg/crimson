# `unused_effect_uv8_prefix_state_global_init`

Exact 28-byte, six-instruction match with all four data references proven.
The initializer writes `{0, 0, 0, 1}` to the anonymous four-word object at
`0x00491000`, immediately between `effect_uv_strip16` and `effect_uv8`.

Live Binary Ninja xrefs show no runtime dereference of this object. The
`0x00491004` reference in `effect_uv_tables_init` is only the one-past V-field
loop bound for the preceding 16-entry strip. The curated name deliberately
retains `unused` and `prefix_state` rather than inventing gameplay semantics.
