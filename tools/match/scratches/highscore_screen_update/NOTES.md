# `highscore_screen_update`

Native target: `crimsonland.exe` at `0x004423d0` (8,026 bytes).

Live Binary Ninja disassembly and decompilation recover the complete high-score
screen callback:

- derives both UI panels from element slots 09 and 33, draws the current-mode
  title, quest selector, score headings, Hardcore toggle, and ten formatted
  score rows;
- distinguishes time-based Rush/Quest records from score-based modes, preserves
  the native internet-record marker, and renders the hovered record detail with
  its one-based rank;
- implements the date, player-count, game-mode, internet-score, and profile
  controls, including the native one/two-player choices and Typ'o'Shooter clamp;
- handles Update/Receive, Shift batch synchronization, every connection status,
  post-sync update checks, and the update-notice widget;
- routes Play, Back, Escape, keyboard quest navigation, and mouse arrow actions,
  including return-to-results pool cleanup and restoration of the saved mode;
  and
- proves all nine local-static destructor thunks at `0x00444330` through
  `0x004443b0` as exact one-instruction returns.

The natural `msvc6.5 /O2 /GB` reconstruction matches 77.21% of 2,004 target
instructions with 1,962 candidate instructions. The candidate has the native
`0x84`-byte frame, a 41-instruction matching prefix, and audited references of
`581/0/8` (ok/unresolved/mismatch). The eight residual reference mismatches are
instruction-alignment or x87 temporary-order differences; every corresponding
field, constant, string, and gameplay object is present in the recovered flow.

The Quest filter performs its unlock-bound check independently in the normal
and Hardcore arms. Native computes the selected quest index in each arm, loads
the corresponding unlock counter, and tail-merges only the identical clamp and
table-reload body. Recovering that shape adds six candidate instructions and
four aligned references. The adjacent Hardcore checkbox gate keeps its enabled
arm as the fallthrough (`quest_unlock_index >= 40`), matching the native branch
layout. Together these changes raise the score from 76.92% to 77.21% and add
23 fuzzy-weighted bytes without changing behavior or the exact frame.

The Shift batch synchronizer at `0x00443b23..0x00443c2a` is a chained
stage machine rather than a switch lowered around shared case tails. Stages
`-3`, `-2`, and `-1` select Survival, Rush, and Typ'o'Shooter through explicit
`if`/`else if` arms. Negative stages then branch directly to the shared sync
start, while nonnegative stages reject normal and Hardcore quest indices
through separate invalid-first comparisons before validating the major stage.
Expressing that native control flow removes an unsupported `start_sync` local,
keeps the exact frame and instruction prefix, aligns ten additional
references, and raises the whole-function score from `75.85%` to `76.92%`.

This remains an honest work in progress: no register hints, dead expressions,
fake aliases, unreachable shaping, or platform substitutions are used.

The score-line builder now carries a typed
`char (*)[164]` cursor through the ten-row backing array. This expresses the
native `+0xa4` row stride directly instead of byte arithmetic, keeps the
evidenced `char *` item table separate from its storage, and is matcher-neutral
at **77.21%**, the exact `0x84`-byte frame, and reference audit `581/0/8`.
