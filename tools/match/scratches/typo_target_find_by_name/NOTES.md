# typo_target_find_by_name

Native target: `crimsonland.exe` at `0x00445590` (98 bytes).

The helper scans all 384 creature slots, considering only active records, and
returns the first index whose 64-byte Typ-o name matches the supplied string;
otherwise it returns `-1`. The native inlined comparison uses the table name as
the left operand. Natural VC6 code matches all 42 instructions and references
`3/0/0`.
