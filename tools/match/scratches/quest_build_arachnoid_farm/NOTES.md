# `quest_build_arachnoid_farm`

Native target: `crimsonland.exe` at `0x00436820` (382 bytes).

Live Binary Ninja evidence recovers three horizontal spawner lines. The first
two contain `config_player_count + 4` template `0x0a` entries, starting at
`(256, 256)` and `(256, 768)` with an x step of 102.4. Their triggers start at
500 and 10500 ms and advance by 500 ms. The middle line contains
`config_player_count + 7` template `0x10` entries at y=512, uses an x step of
64, and advances triggers from 40500 ms in 3500 ms steps. Every entry has
count one, so the normal one-player table contains 18 entries.

Whole-vector construction is the decisive source-shape recovery: it reproduces
the native 12-byte frame, x87 conversion spills, fixed-y hoists, and complete
loop bodies. Scoped line indices share the native stack slot. The positive
third-line path writes the output count and returns, matching the native dual
epilogue without dummy control flow. The candidate has the same 112
instructions, preserves a 12-instruction prefix, all ten references, and
scores 93.75%.

The residual seven instructions are three independent VC6 allocation choices:
the first two line bases and their scaled entry index trade EAX/EDX, while the
third-line bound uses `lea eax` instead of destructively adding seven to EDX.
A per-entry pointer, post-incremented pointer, `msvc6.5pp`, `msvc7.0`, and
`/G6` were checked and regress. The exact-length default-profile form is kept
without forced registers or artificial dependencies.

## Recorded line-bound search

`line-bound-mutations.json` exhaustively evaluated all 124 single, pair, and
triple combinations of named top, bottom, and middle line bounds. Every cached
bound loses an instruction and one or more global references; the best such
variant drops 56.64 weighted bytes. This confirms that the native repeatedly
loads `config_player_count` rather than preserving one derived bound, despite
the final destructive `add edx, 7` allocation. The complete negative matrix is
recorded in `experiments.jsonl` (spec
`c0701e97213920a151df1226955167aabd43ef2cf0ebb18eedc1fbab9f00e944`).

## Recovery classification audit

The preceding BN recovery accounts for the complete control-flow, call (where
present), constant, record-store, and output-count policy. The candidate has
the same instruction count as native and all masked references resolved; its
localized residual is compiler scheduling/allocation only. Classification:
`RECOVERY=semantic-complete`, `RESIDUAL=compiler`.
