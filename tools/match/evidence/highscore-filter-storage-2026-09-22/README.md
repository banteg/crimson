# Highscore filter storage and large-frame ordering

This package explains the stack allocation of five source witnesses for
`highscore_screen_update`. It predicts all **182 symbol offsets**, including
anonymous compiler spills, and independently checks each emitted 132-byte
frame. All five observations preserve the complete COFF object except its
timestamp and reject a withheld frontend stream. No compiler decision changes.

The canonical source is unchanged: 1,978/2,004 instructions, prefix 45,
references 592/0/4, and both exactness flags false. None of the alternate
sources has a whole-UI execution proof or is promoted. Exact coverage remains
804/810. The controls are evidence about source/compiler behavior, not a claim
that these were the original source variables.

## The additional allocator rule

The earlier [HUD model](../hud-stack-coloring-2026-09-10/README.md) groups locals
by size, use count and bidirectional interference. Highscore follows those
same grouping rules, but its groups total **129 bytes before alignment**.
C2 `0x4b617` invokes another pass when that total is greater than `0x80`:

- `0x61bf0` sorts groups by `floor(1000 * counted_uses / size)`, descending.
- Its quicksort uses the middle group as pivot and a strict greater-than
  comparison. Equal densities do not have a stable ordering.
- The observed allocation path visits the resulting groups backwards,
  subtracting their sizes and applying alignment. The one-byte hover flag is
  not itself rounded to four bytes; padding appears when the next group needs
  it. The final local frame is rounded to four bytes.

For the cumulative row/panel witness, the hover flag and right-panel group
both have density 4,000. Native compiler tie handling places the right-panel
group first. A stable Python sort predicts different offsets and is rejected.
The other four witnesses do not distinguish stable versus native tie handling;
their receipts do not count that as a negative control.

The verifier reconstructs groups from the captured order, sizes, counts and
conflict sets. Observed final offsets are used only to check the prediction.
It checks named descriptors at byte offset `0x0c` and anonymous spill offsets
in the compiler symbol at byte offset `0x28`. This is scoped to the observed
zero-parameter, reverse-allocation path and captured sizes, not a general VC6
stack allocator implementation.

Observation uses the same pinned compiler and entry points as the HUD proof:
`0x33cde -> 0x4b617` before coloring and `0x5840f -> 0x34032` afterwards.
Globals `0x9f220`, `0x9f218`, `0x9f204` and `0x9f20c` provide the ordered list,
indexed symbols, interference sets and count. Additional read-only IR traversal
records source lines for named operands. Source lines are diagnostic attribution;
they do not identify the native source's owners. Raw pointers remain in the
temporary trace; the retained summary uses per-trace indices.

## What the source controls establish

The starting cumulative witness is reconstructed from the earlier
[prefix-lifetime package](../highscore-prefix-lifetime-2026-09-22/README.md).
The 30 controls here include that witness, the canonical baseline, and 28
additional source forms, each with checked edits, source/body hashes and full
matcher metrics.

| Control | Concrete observation | Unresolved problem |
| --- | --- | --- |
| Reuse the right panel for the final widget | Its address escapes; the compiler recomputes filter Y sums across calls. | It also reloads/copies X values differently and changes other allocation. |
| Separate widget X, label X, player/game X and shared row Y | Some native coordinate operations return; frame remains 132 bytes. | The explicit label scalar receives a stack home absent from the corresponding native sequence. |
| Move label X before/after the version call | Both variants retain the same unwanted local; changing call timing alone does not remove it. | The native post-call `mov edi` is still not recovered. |
| Use byte, integer or boolean version results | Byte and boolean forms can change the distant row allocation/call-tail shape; integer widening adds operations. | Local similarity cannot establish a safe whole-function recovery. |
| Put player items before the date widget | The item array and player widget exchange storage groups, reaching their native -88 and -72 homes. | Array initialization also moves earlier than native. Slot agreement alone is insufficient. |
| Copy widget coordinates or reverse the two additions | Component/vector copies do not remove the unwanted Y-sum reuse; reversing label/widget additions is body-byte neutral. | These bounded source forms do not control the common-subexpression decision. |
| Replace the scrollbar's two-iteration clear with direct stores | Removes the loop. | Zero-value lifetime and later allocation still differ; an equal instruction count in a combined control is not a match. |

The most closely aligned tested body is `filter-copy-after-constructor` at
87.060583%, 2,007/2,004 instructions, prefix 105 and references 616/0/4. It still
has non-native copy scheduling and stack homes. That score is a diagnostic,
not the reason to retain a source change. The canonical source remains intact.

## Verified storage constraints

All five traces have 13 groups and raw/aligned sizes 129/132. The cumulative
witness's right-panel group contains 32 counted uses over eight bytes,
including later objects that can share that storage. The explicit snapshot
witness gives the right panel its own 31-use group. Density falls from 4,000
to 3,875, moving it below the hover flag and changing its offset from -124 to
-120. This explains the movement without attributing it to declaration order.

In the snapshot witness, the group containing selected score, label X, option
label Y, row Y and online/profile/date positions has density 2,125. It precedes
the 2,000-density group containing separator/scrollbar/back/notice positions.
Their resulting -104/-96 offsets are the reverse of the corresponding native
uses. Moving label X after the version call leaves these groups intact. The
integer-return control instead adds another use to the first group, raising
its density to 2,250 without fixing the order.

Extending the player-item array lifetime across the date widget changes its
conflicts. The model predicts its exchange with the player-position object;
group sizes, densities, and all other resulting offsets stay unchanged.
The earlier native stack map remains the reference for intended homes:
[native storage map](../highscore-residual-decomposition-2026-09-13/README.md#compiler-storage-evidence).
Equal native offsets still do not establish that the original source reused
one object.

The next constraint is to recover the native Y recomputation and X copies
without introducing the extra label owner or wrong initialization stage.
Changing the compiler's counts or assigning native offsets directly would
only bypass this source-recovery problem.

## Reproduce

```sh
UV_CACHE_DIR=/private/tmp/crimson-uv-cache uv run --no-sync python \
  tools/match/evidence/highscore-filter-storage-2026-09-22/controls.py \
  --out /private/tmp/highscore-filter-controls
UV_CACHE_DIR=/private/tmp/crimson-uv-cache uv run --no-sync python \
  tools/match/evidence/highscore-filter-storage-2026-09-22/verify.py \
  --out /private/tmp/highscore-filter-storage
```

Both output directories must be new. The control runner force-compiles every
source against the pinned baseline `b9bab229d28a8c4b11549bdaae8504048948ebe4`.
The observer independently builds its five selected controls, captures/replays
all frontend streams and checks whole-object preservation.

The 21 model/trace negative controls reject changed offsets, truncated graph
data, omitted large-frame sorting, omitted byte padding, and the inappropriate
stable tie rule where it is distinguishable. Five additional missing-stream
checks are in the capture receipts. No filter execution equivalence is claimed;
the earlier row-execution proof covers only its specifically named sources.
