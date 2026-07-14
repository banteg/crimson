# `time_format_mm_ss`

Exact 105-byte, 37-instruction match with MSVC 6.5 `/O2 /GB`; all eight masked
references align (the static output buffer, two format literals, two
`crt_sprintf` calls, and repeated operands).

The helper computes the signed remainder once, chooses `%d:0%d` for seconds
below ten and `%d:%d` otherwise, and returns the shared buffer. The ordinary
`%` and `/` expressions intentionally reproduce VC6's paired signed-division
lowering; no arithmetic shortcut or formatting fakematch is involved.
