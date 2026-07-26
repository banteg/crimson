# `grim_missing_frame_callback`

Native target: `grim.dll` at `0x10001140` (13 bytes).

This is the default engine callback installed when no frame function has been
provided. It stores the immutable
`"System: No Frame Function defined."` diagnostic in `grim_error_text` and
returns false.

The string is represented by its address-keyed data symbol rather than a
compiler-local literal label. This preserves the observed source semantics
while allowing the masked address reference to be audited across tools.

VC6 `/O2 /GB` produces all 3 normalized instructions with full prefix and
reference agreement `1/0/0`.
