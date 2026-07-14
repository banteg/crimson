# `dx_version_compare_4x16`

Exact 45-byte, 17-instruction match with MSVC 6.5 `/O2 /GB`; the function is
pure and has no masked references.

The helper compares the unsigned high version dword first, then the unsigned
low dword. It returns `1` when the current version is newer, `-1` when older,
and `0` for equality. The straightforward ordered branches reproduce the
native final `cmp`/`sbb` lowering exactly.
