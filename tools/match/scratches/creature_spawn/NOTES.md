# `creature_spawn`

Native target: `crimsonland.exe` at `0x00428240` (334 bytes).

Live Binary Ninja evidence recovers the complete rush-mode creature
initializer. It allocates one creature slot, copies the caller's position and
type, and initializes orbit-player AI with cleared collision, force-target,
attack-cooldown, and velocity state. The creature starts active with state flag
one and lifecycle stage 16. Its elapsed-time-derived values are:

- health: `survival_elapsed_ms * 0.000100000005 + 10`;
- move speed: `survival_elapsed_ms * 1.00000007e-5 + 2.5`;
- size: `survival_elapsed_ms * 1.00000007e-5 + 47`.

The function consumes two random draws. Heading is `(rand() % 314) * 0.01`,
and reward is `rand() % 30 + 140`. It copies all four caller-provided tint
components, sets contact damage to four, and copies health into max health
before returning the allocated slot.

The legacy `oldtypes.h` declaration `SpawnCreatureEx(vec2_t spot, color_t col,
int)` proves the two caller aggregates. The lowered matching boundary now uses
`const vec2f_t *pos` and `const effect_color_t *tint`; source and saved Binary
Ninja types expose `x`/`y` and `r`/`g`/`b`/`a` instead of six raw float
indexes. The destination position is likewise copied through the canonical
`creature_t::position` aggregate instead of two provisional scalar aliases.
That source-shape recovery is byte-neutral. Binary Ninja also types the
embedded destination beginning at `creature_t::tint_r` as
`effect_color_t *creature_tint`; materializing that aggregate destination
owner in the source recovers the native `lea`-based tint publication.

The native function explicitly materializes two zero words in its eight-byte
stack frame before reading them back as the creature velocity. The matching
source keeps that observed storage overlay, but names its float view as a
`vec2f_t zero_velocity` instead of exposing anonymous parallel `int[2]` and
`float[2]` indexes. A plain initialized `vec2f_t` is not equivalent under this
C front end: VC6 folds it away, deleting the native frame and six
instructions. The named overlay is byte-neutral at 86.08%, 79/79 instructions,
and 27/0/0 references.

The candidate has the exact 79-instruction length, resolves all 29 audited
references, and scores 88.61% with a seven-instruction exact prefix. Its
remaining differences are instruction scheduling rather than missing behavior:
the scratch compiler hoists the first elapsed-time x87 calculation through
independent record stores and starts the final size calculation during the tint
copy, while native leaves both calculations close to their stores.

The direct `creature_pool[slot_id]` form is significant. Replacing it with a
local `creature_t*` changes the native global-base-plus-index addressing into
an absolute record pointer, drops one instruction, loses reference alignment,
and falls to 61.15%. Compiling the identical source as C++ or with `msvc6.6`
does not change the best candidate; `msvc6.5pp` and `/G6` regress to 83.54%
and 75.95%. No volatile state, artificial aliases, dummy work, or ordering
barriers are used.

The Python and Zig rush-mode spawn models already preserve the native formulas,
two RNG call sites, four-component tint, and max-health copy, so this audit did
not reveal a port-parity correction.

## Recorded mutation evidence

The native tint tail at `0x00428331..0x00428382` constructs a destination
pointer before copying the four-component aggregate. Expressing that same
owner explicitly raises the global match from 86.075949% to 88.607595%, keeps
79/79 instructions and prefix 7, improves references from 27/0/0 to 29/0/0,
and reduces the weighted byte gap from 46.506329 to 38.050633. Manual member
copies lose the native destination owner, swapping contact damage and
max-health publication or staging max health regress, and replacing the two
observed velocity stores with an aggregate assignment falls to 64.102564%.
Only the tint destination-owner recovery is retained.

Two complete, recorded mutation matrices cover 53 ordinary source-shape
variants without retaining a change. `initializer-schedule-mutations.json`
evaluates 24 single and paired tint/size scheduling alternatives; its best
`size-between-tint-and-scalars` form is byte-neutral.
`field-init-order-mutations.json` evaluates 29 zero-storage and field-order
alternatives. Four natural zero-initializer spellings are also byte-neutral,
while moving `active` ahead of the clears changes reference alignment or
regresses the score. Their specification SHA-256 values are
`2b2320d4b5e9e40bd13181ac371e8d32e9095c203bca618354e0d472423cf3b3`
and
`b9ae36e738f49449b48c0387faa63cb850526ea0b0aea248c0b0c7456e2a5258`.
This rules out the remaining obvious initializer-order interactions rather
than treating the 86.08% baseline as an untested source preference.

## Recovery classification audit

The live native body still contains the same 79 instructions and complete
initializer policy described above. Focused regions isolate only x87
scheduling: native finishes the elapsed-health expression near its store and
starts the final elapsed-size expression after the tint copy, while stock VC6
keeps those values live across independent stores. All 29 masked references
resolve to the intended globals, calls, constants, and record fields.

Classification is `RECOVERY=semantic-complete`, `RESIDUAL=compiler`. The
retained destination-owner recovery produces 88.61%, prefix 7/79, 79/79
instructions, and references 29/0/0.

`elapsed-expression-lifetime-mutations.json` records 24 compile-valid
single/paired integer-snapshot, float-snapshot, named-result, and staged-result
forms for the health and size expressions (spec
`f9e49f8e6fbebfee744dba7c7ec2647f19238d81ecbca3fe57d7cd3e3106df72`).
Ordinary integer snapshots and named results are byte-neutral; float or staged
forms regress by 4.23 weighted bytes and can disturb reference alignment.
None delays either x87 chain to the native schedule, so **86.08%** remains the
recorded pre-owner baseline rather than the current result.

## Current tint-owner replay (2026-08-11)

The retained aggregate tint destination raises the live baseline to 88.61%
and changes the tail's allocation graph, so all three historical scheduling
matrices were replayed against that source.

- The complete 24/24 `elapsed-expression-lifetime-mutations.json` matrix has
  14 byte-identical integer/result forms and ten health-staging regressions.
  No health/size interaction moves either x87 chain toward native.
- The complete 29/29 `field-init-order-mutations.json` matrix keeps four
  zero-storage forms byte-identical. Moving `active` is score-neutral but loses
  one aligned reference; every other field-order family regresses.
- The old initializer-schedule plan no longer matches the aggregate tint-owner
  block. Its current replacement,
  `current-initializer-schedule-mutations.json` (SHA-256
  `4c32b264a03364899ba0b99d8b546ab46c73a9c26913b00cfa2f739cb737fde1`),
  evaluates all 24/24 generated combinations. The only valid byte-neutral form
  moves size between the tint copy and the scalar tail; fourteen valid forms
  regress. Nine named-local combinations do not compile because their
  declarations follow statements under the scratch's C89 mode, so they are
  recorded as invalid rather than treated as source evidence.

Across 77 current-baseline evaluations, no tradeoff-free variant improves the
88.61%, 79/79-instruction, prefix-seven, `29/0/0` source. `scratch.c` remains
unchanged. The complete seven-line experiment log now has SHA-256
`f88e42d37a8afeabc089acde7d106dd60ca2f403dd00931218ab5ff35f7b0855`.

## Focused follow-up (2026-09-05)

Seven C++ velocity-constructor and position/color class-copy forms were
tested. The unchanged C source compiled as C++ is byte-neutral at 88.61%. Real
vector constructors either remove the six native zero-storage instructions or
retain the extent but regress to 86.08%; class-copy identities are neutral.
The recorded /TP flag selects the C++ frontend only; canonical compiler
settings and C source remain unchanged.

The complete bounded matrix is recorded in
`cpp-velocity-owner-followup-mutations.json`. No source change is retained;
this result bounds these specific hypotheses only.

## Batch 02 focused value boundaries (2026-09-05)

`batch-02-focused-value-boundaries-mutations.json` records 4 complete, compiling
controls against the 88.607595% baseline. The source forms are `record-owner`,
`health-value-before-publish`, `color-value-copy`, `size-before-color`.

No control improves the retained baseline without a metric tradeoff. Canonical source
and configuration are unchanged. These results bound the recorded hypothesis, not the
function's matchability.
