# Creature-update arithmetic and store order

The recovered `creature_update_all` matches native state, callback arguments,
and ordered writes in all **2,472** recorded scenarios. The preceding source
differs in 460 state/callback traces and 886 write traces. The static score
improves from **54.91088358% to 54.95256167%**, or **2.221442 weighted bytes**.
It remains WIP: 1,297 candidate instructions against 1,338 native instructions,
`225/0/2` aligned references, neither normalized-exact nor encoded-body-exact.

Four source edits account for the recovery:

| Region | Native evidence and recovered behavior |
| --- | --- |
| Initial player distance | `0x00426438` executes `fsqrt`, followed by the float store at `0x00426440`. Remove the candidate's two additional reciprocal divisions. Keep the vector-expression boundary and return a named float length. |
| Both live movement branches | Multiply the trigonometric result by frame time, movement scale, movement speed, then 30. VC6 had reordered the speed factor ahead of frame time. The recovered expression emits the native factor order; single-precision x87 fixtures expose the old rounding differences. |
| Stationary spawner velocity | Native clears Y at `0x00426c61`, then X at `0x00426c68`. A chained assignment reproduces these writes. The separate corpse branch retains its native X-then-Y order. |
| Hold timer | Publish target X and Y before the decremented radius, matching stores at `0x00426a4b`, `0x00426a52`, and `0x00426a59`. |

The historical SDK-style reciprocal helper was a useful source-shape lead,
but its current compiled body contained operations absent from native. The
execution evidence corrects that earlier native-codegen claim. Neither the
source declaration `semantic-complete` nor an improved fuzzy score establishes
numerical equivalence.

## Reproduction and observation

```sh
uv run --no-sync --with unicorn==2.1.4 python \
  tools/match/evidence/creature-state-publication-2026-09-11/verify.py \
  --out /private/tmp/crimson-creature-publication-proof
```

Unicorn needs permission to allocate executable memory on macOS. The optional
dependency is not added to the project. `before.cpp` pins the preceding source;
`recover.py` reconstructs each intermediate and the exact current source.
The verifier compiles both sides with the configured VC6 profile and relocates
the candidate COFF using actual symbol/addend records. It does not use fuzzy
alignment to direct execution.

Both programs start from the same PE image and fixture state. Native
`angle_approach`, `vec2_add_inplace`, and `crt_ftol` execute unchanged. Other
callbacks record their exact argument words and use documented shared models:
perk queries return fixture membership, `rand` returns deterministic values in
0..32767, and queued corpse effects return the fixture result. The optional
damage model subtracts health as float32. The normalization callback uses a
shared vector model; it does not execute or prove the D3DX implementation.
Other callbacks return zero and do not model their game-side effects.

The observer compares the entire creature pool, both player records, all spawn
slots, five touched scalar globals, CPU write order, modeled damage writes,
and callback order/argument bits without tolerance. It checks stack balance,
callee-saved registers, x87 control-word preservation, unexpected execution,
instruction limits, and writes outside the explicit state regions. Pointer
arguments that refer to caller temporaries compare the consumed vector/color
words. Compiler-generated fixture offsets and sizes are checked against the
shared headers before execution.

Fixtures include both 24-bit and 64-bit x87 precision, all nine AI modes,
retargeting, links and timers, freeze/death/fade transitions, spawner limits,
animation wrapping, contact/ranged thresholds, perks, shields, infection,
Energizer, nonzero damage/reward/color values, the final pool slot, and a full
frozen pool. Selected cases vary initialized stack contents. This matters for
the native path that consumes an unassigned alternate-distance local; its
observed result is conditional on that fixture's stack contents.

The cases execute **1,332/1,338 native** and **1,291/1,297 candidate**
instructions. The six unexecuted instructions on each side handle negative
`rand()` remainders, outside the shared model's return range. Instruction
coverage does not prove every path, input, interleaving, or floating-point
value. The static byte and reference differences remain unresolved.

Two additional deliberately incorrect sources are detected: omitting slot 383
changes state and writes; doubling contact damage changes callback arguments.
`results.json` retains hashes of the image, compiler, sources, helpers, loader,
fixture definitions, generated cases, and each observation, plus before/after
metrics, coverage, mismatch witnesses, and control outcomes. Reproduction writes
the complete concrete cases and temporary source variants to the output folder.
