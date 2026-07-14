# `effect_uv_tables_init`

Exact 356-byte, 109-instruction match with MSVC 6.5 `/O2 /GB`; all 15 masked
references align.

Live Binary Ninja evidence shows one native caller,
`game_startup_init_prelude` at `0x0042b0e7`. The function fills an unnamed
16-entry horizontal strip at `0x00490f80` with `(x / 16, 0)`, followed by the
known 2x2, 4x4, 8x8, and 16x16 effect-atlas tables. The vector at `0x00490f78`
is a separate adjacent object, not the table base.

Source shape is material. The horizontal strip is a normal indexed `for` loop.
Each square table instead walks explicit pointers to the V field for the
current row and cell; VC6 hoists the row V value onto the x87 stack across the
inner loop. Flattened indexed loops compute the same values but lose the native
ESI row counter and pointer strides.

The Python atlas helpers already derive the same power-of-two UV coordinates.
All native fractions here are exact binary values, so no runtime parity change
is required; the port provenance comment now uses the recovered function name
and includes the horizontal strip.
