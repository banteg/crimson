# `input_scheme_label`

Exact 53-byte, 17-instruction match with MSVC 6.5 `/O2 /GB`; all seven masked
references verify. Six references are the returned label strings and the
seventh is the five-entry compiler-generated switch table, whose linked case
destinations match the COFF table structurally.

The helper maps schemes `1..5` to `Relative`, `Static`, `Dual Action Pad`,
`Mouse point&click`, and `Computer`; every other value returns `Unknown`.
The contiguous switch is the natural native source shape and produces the
unsigned range check plus jump-table dispatch seen in the executable.
