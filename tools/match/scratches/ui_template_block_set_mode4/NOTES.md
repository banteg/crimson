# `ui_template_block_set_mode4`

Exact 13-byte, 3-instruction match with MSVC 6.5 `/O2 /GB`; the helper has no
masked references.

The argument is passed in `ECX`, proving `__fastcall`/this-like calling shape.
It sets `ui_menu_item_subtemplate_block_t.quad_mode` at offset `0xe4` to four
and returns the same block pointer in `EAX`.
