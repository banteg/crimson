# `quest_spawn_table_empty`

Exact 39-byte, 16-instruction match with MSVC 6.5 `/O2 /GB`; both masked
references align to the active count and spawn table.

Live Binary Ninja shows two calls in `quest_mode_update`. The helper scans the
active quest spawn entries backwards and returns false on the first positive
remaining count; zero and negative counts are exhausted. An empty table
returns true.

Only AL is defined on either return path, proving the helper's result is a
byte-sized boolean rather than the earlier decompiler-inferred `int`.
