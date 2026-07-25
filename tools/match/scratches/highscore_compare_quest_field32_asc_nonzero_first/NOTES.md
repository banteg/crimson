# `highscore_compare_quest_field32_asc_nonzero_first`

Exact 53-byte, 22-instruction match with MSVC 6.5 `/O2 /GB`. It sorts
`survival_elapsed_ms` ascending, but returns `1` immediately for a zero left
value and `-1` for a zero right value, placing missing/unfinished records last.
Nonzero values use signed comparisons.

The Python Quest key `(value == 0, value)` implements the same ordering and is
covered by the existing mode/highscore tests.

The Binary Ninja presentation signature uses `const highscore_record_t *`
arguments, so the zero-last control flow now names
`survival_elapsed_ms` instead of loading anonymous offset `0x20`. The exact
compiler-facing qsort callback remains `const void *` with explicit casts.
