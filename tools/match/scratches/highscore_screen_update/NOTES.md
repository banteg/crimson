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

The left panel origin is one chained vector expression:
`element position + first vertex + (300, 40)`. Native keeps the first sum and
the final sum in separate temporary slots before copying the result into the
live screen cursor, exactly as the same source idiom does in the recovered
options and Alien Zoo Keeper screens. Replacing the named intermediate
`operator+=` with that value expression keeps all 1,962 candidate instructions,
the exact frame, and `581/0/8` references while improving the prefix from 41 to
45 instructions, the score from **77.21%** to **77.31%**, and fuzzy coverage by
8 bytes. Applying the analogous rewrite to the later right panel was measured
separately and rejected because it disrupts the aligned lifetime map.

Native then advances the live cursor component by component: `x` starts from
the chained panel result before adding the UI render offset and constants, while
`y` adds one independently. Expressing those two scalar assignments instead of
constructing another temporary vector keeps all 1,962 instructions and the
45-instruction prefix, improves the score to **77.36%**, adds another 4 fuzzy
bytes, and improves the reference audit from `581/0/8` to `583/0/7`.
Reading the already-copied panel components directly was also isolated, but
lost 8 fuzzy bytes and one aligned reference; keeping the live `position`
assignments preserves the native lifetime implied by the copy.

The native score-row loop carries three distinct induction pointers: a
`char **` cursor through the ten item slots, a `uint8_t *` cursor anchored at
`highscore_record_t::flags`, and a `char (*)[164]` cursor through the row
buffers. Binary Ninja now retains those names and types, along with the
row count, escape-prefix length, and three branch-local player-name pointers.
The record cursor deliberately remains an interior byte pointer: previewing it
as `highscore_record_t *` mislabeled `flags` as `player_name[0]`, because the
native register contains `&record->flags`, not the owning record base. The
remaining negative offsets are therefore honest evidence of VC6's interior
induction variable rather than missing owner-type recovery.

The stack slots holding score number and selected row are coalesced with
unrelated render coordinates and later item pointers. Split-local type
previews polluted those other lifetimes, so they are intentionally left
unannotated until Binary Ninja can represent the compiler's stack-slot
lifetime splits without widening the user type across the whole function.

The matching source now carries the score-record walk as the native
`unsigned char *` cursor anchored at `highscore_record_t::flags`, advances it
by the proven `0x48` record size, and recovers the owning record with
`offsetof` only where the name, elapsed time, or score is needed. It also
clears each row through the item pointer just assigned to that row, preserving
the target's item-before-clear data flow without raw offsets. This raises the
whole-function result from **77.36%** to **77.42%**, adds 4.70 fuzzy-weighted
bytes, and reduces the candidate from 1,962 to 1,959 instructions while
retaining the 45-instruction prefix and `583/0/7` reference audit.
