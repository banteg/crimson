# `ui_template_triplet_reset_and_seed_modes`

Exact 48-byte, 12-instruction match with MSVC 6.5 `/O2 /GB`; the helper has no
masked references and uses the same `__fastcall`/this-like pointer ABI as the
single-block initializer.

The three mode stores at `+0x120`, `+0x208`, and `+0x2f0` are separated by
`0xe8`, exactly the recovered size of `ui_menu_item_subtemplate_block_t`.
That identifies a three-block array beginning at parent offset `0x3c`, now
captured by `ui_menu_template_triplet_t`; the remaining stores reset the parent
head and tail state fields before returning the parent pointer.
