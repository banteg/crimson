# highscore_submit_full_version_guard

Native target: `crimsonland.exe` at `0x0043aa60` (38 bytes).

The guard forwards its record pointer to the constant full-version predicate,
prints the illegal-score warning only when that predicate returns zero, then
returns one. Live disassembly proves the call at `0x0043aa65` targets
`game_is_full_version` at `0x0041df40`; that callee is `mov al, 1; ret` and is
shared by the rest of the demo/full-version gates.

The local old-style C declaration intentionally preserves the native extra
record argument while emitting the real `_game_is_full_version` identity.
This replaces the unsupported `highscore_record_is_valid` name without
changing code: the result remains exact at 12/12 instructions and `4/0/0`
references.
