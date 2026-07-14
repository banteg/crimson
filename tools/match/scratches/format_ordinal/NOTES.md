# `format_ordinal`

Exact 96-byte, 33-instruction match with MSVC 6.5 `/O2 /GB`; all eight
masked references align.

The native helper formats a signed integer into a shared buffer with one of
`st`, `nd`, `rd`, or `th`. Its `8..20` fast path selects `th` without taking a
remainder; for positive ranks this is equivalent to the familiar `11..13`
exception because every other value in that interval naturally ends in a
non-special digit.

Live Binary Ninja evidence shows one caller, `ui_text_input_render`, where the
result supplies the high-score `Rank: %s` label. The buffer and suffix literals
are modeled as real data references so the match must pass relocation auditing.
