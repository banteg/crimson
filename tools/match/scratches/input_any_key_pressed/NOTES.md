# `input_any_key_pressed`

Exact 40-byte, 16-instruction match with MSVC 6.5 `/O2 /GB`; the sole masked
reference resolves to `grim_interface_ptr`.

The function scans extended input ids `2..0x17e` through the Grim2D
`grim_is_key_active` virtual method. A pre-tested `while (key < 0x17f)` is the
native source shape: VC6 proves the initial bound from `key = 2`, emits one
shared call loop, returns `1` on the first active key, and otherwise returns the
low byte from the final inactive query. A `do` loop causes VC6 to peel the
first iteration and does not match.
