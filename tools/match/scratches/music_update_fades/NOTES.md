# sfx_update_mute_fades

For each loaded music entry, this keeps audible tracks playing, fades muted
tracks down at half the frame delta, and ramps unmuted tracks toward the music
volume at the full frame delta. Crossing zero stops all voices and clamps a
negative accumulator on the following check; overshooting the target volume is
clamped immediately. A non-positive configured volume directly stops the
primary buffer before the same mute/volume reconciliation.

Live instructions at `0x0043d6c7..0x0043d6e4` reload the newly computed
volume, compare it with the configured target, and take the local-volume arm
when it is less than or unordered. Expressing the clamp as the positive
`volume >= music_volume` arm preserves that native short-circuit boundary and
raises the VC6 `/O2 /GB` result from 83.76% to 84.48%. The weighted gap falls
from 60.7350 to 58.0345 bytes, with 118 target instructions, 114 candidate
instructions, and all 26 references still audited. That source was the
baseline for the bounded mutation sweep below.

The remaining delta is compiler shape: native spills each newly computed
volume to the local and table, pops the x87 value, then reloads the local
before comparison. The original plausible source kept that value live; the
chained assignment retained below instead duplicates the live x87 value before
the table store, rather than performing the native stack reload.

## Bounded mutation sweep

The `crimson match mutate` harness evaluated all nine one-site variants from
`volume-shape-mutations.json`, whose spec SHA-256 is
`51c14e07f9f44fcc4cff7ea386eeb917e17f5106329001c70a4e00fae9e7ded2`
with `--max-changes 1 --record`. The three explicit sites covered the muted
volume computation, audible ramp computation, and final clamp. Each computation
tested a branch-local value plus local-first and table-first chained assignment
orders; the clamp tested shared-local, branch-local, and stored-table reuse.
Coverage was complete at 9/9 variants with no unevaluated combinations at the
requested depth.

Full ranking:

1. `final-clamp-shape/stored-value-reuse`: 85.47%, gap 54.3419,
   116/118 instructions, `27/0/0` references.
2. `ramp-volume-shape/chained-local-first`: 84.98%, gap 56.1803,
   115/118 instructions, `26/0/0` references.
3. `muted-volume-shape/chained-local-first`: 84.98%, gap 56.1803,
   115/118 instructions, `26/0/0` references.
4. `ramp-volume-shape/chained-table-first`: 84.48%, gap 58.0345,
   114/118 instructions, `26/0/0` references.
5. `muted-volume-shape/chained-table-first`: 84.48%, gap 58.0345,
   114/118 instructions, `26/0/0` references.
6. `final-clamp-shape/shared-local-reuse`: 82.20%, gap 66.5593,
   118/118 instructions, `26/0/0` references.
7. `final-clamp-shape/branch-local-reuse`: 82.20%, gap 66.5593,
   118/118 instructions, `26/0/0` references.
8. `ramp-volume-shape/branch-local`: 79.31%, gap 77.3793,
   114/118 instructions, `26/0/0` references.
9. `muted-volume-shape/branch-local`: 79.31%, gap 77.3793,
   114/118 instructions, `26/0/0` references.

The winner separates the final table assignment from the call and then passes
the just-stored table value. There is no intervening call or mutation, so this
is semantically identical to the assignment expression. It reproduces the
native `0x0043d6f5..0x0043d700` load/store/register-reuse sequence, adds two
candidate instructions and one resolved reference, improves the score by
0.99 percentage points, and closes 3.6926 weighted bytes. The recorded sweep
is in `experiments.jsonl`.

## Chained-assignment interaction sweep

A second recorded sweep started from the improved 85.47% baseline and tested
only the two individually positive `chained-local-first` variants.
`chained-local-first-interaction-mutations.json` has spec SHA-256
`4e2c7827207ba88aa266fc9fbdbf2ee6beef1b90a2a0d4692b437c973f46dd30`
and ran with `--max-changes 2`: both singles were evaluated, followed by their one
possible interaction, for complete 2/2 single and 1/1 pair coverage.

- Muted computation alone: 85.96%, gap 52.5191, 117/118 instructions,
  `27/0/0` references.
- Ramp computation alone: 85.96%, gap 52.5191, 117/118 instructions,
  `27/0/0` references.
- Both computations: 86.44%, gap 50.7119, 118/118 instructions,
  `27/0/0` references.

Each single closes 1.8227 weighted bytes. Their arithmetic sum is 3.6455
bytes; the combination closes 3.6300 bytes, only 0.0154 byte less. The effects
are therefore nearly additive, with a small whole-function alignment
interaction rather than interference between the two computations.

Both replacements preserve the same assignment values and ordering:
`volume` receives the computed value before the identical value is stored in
the current table slot, with no intervening side effect. VC6 changes each
former missing pop/reload pair into `fld st(0); fstp [table]`; the native body
uses `fstp [table]; fld [local]`. The natural combined source improves both
localized regions without volatility or artificial liveness and is retained.

## Recovery classification audit

Fresh Binary Ninja HLIL confirms the guard, loaded-entry scan, audible restart,
mute fade, stop/clamp boundaries, unmute ramp, overshoot clamp, and volume
calls. The candidate now emits 118 instructions against 118 native instructions
with `27/0/0` references. The final clamp is recovered; the remaining localized
regions reflect the documented computed-volume x87 duplication versus native
spill/reload and resulting control-flow layout, so recovery remains
`semantic-complete` with a `compiler` residual.

## Computed-volume spill follow-up

Live Binary Ninja disassembly reconfirmed the two native computation sequences:
each stores the x87 result to the shared local, pops it into the table slot, and
then reloads the local for the comparison. A complete recorded 24/24 sweep
(`computed-volume-spill-mutations.json`, spec SHA-256
`94a52255e039d3b118f95030c211253905a3877223b84bd461693681fe12e734`)
tested comma-sequenced assignments, comma-expression reuse, scoped references,
scoped pointers, and every two-site interaction.

The reference and pointer spellings compile byte-identically to the retained
86.44% source. Each comma spelling removes one candidate instruction and loses
1.8073 fuzzy-weighted bytes at one site; their interactions do not recover the
native spill/reload order. No variant improves the baseline, so the natural
chained assignments remain canonical and the negative result is recorded.

## Fresh profile and region recheck

VC6.0, VC6.5, and VC6.6 remain byte-identical at 86.4407%, a
50.7119-byte fuzzy gap, 118/118 instructions, a three-instruction prefix, and
`27/0/0` references. Processor Pack falls to 52.36%; VC7 does not produce an
evaluable candidate. The only x87 lifetime regions are still the two computed
volume spill/reload sites already covered by the complete 24-variant sweep.
No new semantic state-machine or call-boundary hypothesis appears, so the
retained source and recorded mutation set remain unchanged.

## Exact stored-volume consumer recovery (2026-09-05)

Current result: **100%**, 118/118 instructions, full prefix, and references
**27 resolved / 0 unresolved / 0 mismatched**. The previous compiler-residual
conclusions are superseded by `stored-volume-consumers-mutations.json`.

Both fade branches update `sfx_volume_table[i]` directly, then use that stored
float for the clamp comparison and the playback-volume argument. The previous
reconstruction instead tested and passed a local expression result, which kept
an x87 value live across the table store. Replacing both consumers recovers the
native store/pop/reload sequence in both branches. Changing only the comparison
regresses and changing only the argument is neutral; their interaction is exact.

The complete seven-variant matrix also confirms that direct assignment, compound
assignment, and shared or branch-local computation temporaries all give the same
exact bytes once both consumers use the table. The retained compound assignments
remove the unnecessary temporary entirely. No compiler settings or float barriers
were introduced, and all seven controls preserve the reference audit.
