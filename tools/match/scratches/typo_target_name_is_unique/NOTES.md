# typo_target_name_is_unique

Native target: `crimsonland.exe` at `0x00445310` (110 bytes).

The helper rejects a proposed name when another active creature slot has the
same Typ-o target string, excluding the supplied creature id. Its result is an
`unsigned char`: native callers consume `AL`, and that width matches the final
success/failure returns exactly. Natural VC6 code matches all 50 instructions
and references `3/0/0`.
