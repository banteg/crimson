# `credits_build_lines`

Native target: `crimsonland.exe` at `0x0040d090` (1897 bytes).

Live Binary Ninja evidence recovers a straight-line population of the credits
table through `credits_line_set`. The source preserves the native sequence of
five writes to index `0x42`: four greeting strings are immediately overwritten
by an empty string. It also records index `0x54` as the base where
`credits_screen_update` later installs ten secret-path lines.

The recovered source is an exact `msvc6.5 /O2 /GB` match: 544/544
instructions, 1897/1897 bytes, and 261/0/0 audited references. Three short
credits strings and the shared empty string are modeled as native data objects
so every reference resolves without aliases or masks.
