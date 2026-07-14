# `highscore_compare_rush_field32_desc`

Exact 32-byte, 13-instruction match with MSVC 6.5 `/O2 /GB`. This is the same
three-way descending comparator shape as Survival, but it reads
`survival_elapsed_ms` at offset `0x20`. Live Binary Ninja ties it to Rush-mode
highscore sorting.

The Python Rush table already sorts elapsed time descending.
