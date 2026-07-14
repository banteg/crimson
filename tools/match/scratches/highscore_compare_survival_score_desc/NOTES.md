# `highscore_compare_survival_score_desc`

Exact 32-byte, 13-instruction match with MSVC 6.5 `/O2 /GB`. The qsort
comparator reads `score_xp` at offset `0x24`, compares it as signed, and returns
`-1`, `0`, or `1` for descending order. Live Binary Ninja identifies it as the
Survival table comparator.

The Python default highscore ordering is already descending by `score_xp`.
Valid scores do not cross the signed boundary, so no port change is required.
