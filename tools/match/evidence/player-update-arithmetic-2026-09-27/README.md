# player_update arithmetic and smoke storage recovery

Three source changes recover the native movement multiplication order, keyboard
turn value lifetime, and smoke-angle stack home. This remains a partial match:
`exact=false` and `body_byte_exact=false`.

| Measurement | Before | Retained |
| --- | ---: | ---: |
| Raw normalized match | 92.7918299489% | 94.8318878460% |
| Local labels masked | 99.3943712148% | 99.7980278009% |
| Labels and scratch registers masked | 99.4656216601% | 99.8693121065% |
| Stack displacements additionally masked | 99.5843724023% | 99.8693121065% |
| Candidate / native instructions | 4215 / 4206 | 4211 / 4206 |
| Clean / unresolved / mismatched references | 916 / 0 / 0 | 918 / 0 / 0 |
| Stack frame | 0x48 | 0x48 |

The masked scores diagnose residuals; they do not grant exact-match credit.
Both builds use the pinned `msvc6.5 /O2 /GB /W3 /GR-` profile. `before.cpp`
preserves the starting source from `a6fd3908e`; the intervening `cc035e42b`
toolchain-cache change does not change these instruction results.

## Native constraints and selected source

1. In the point, pad, keyboard and demo acceleration paths, native multiplies
   the trigonometric result by `move_speed` before the turn attenuation,
   `speed_scale`, and final constant. Parenthesizing the first product in all
   eight lanes preserves that grouping through C1/C2. The earlier source
   allowed C2 to interchange the first two multiplications. The parentheses
   express the observed arithmetic association; no dummy declarations or
   unrelated expressions inflate compiler symbol IDs.
2. At `0x4144dc` and `0x414520`, native stores the updated `turn_speed` with
   `fst`, retains its live x87 result for the body heading, then reloads the
   field for the aim heading after the body store. A named
   `current_turn_speed` used only for the first heading reproduces this.
   Using it for both headings loses the native field reload; assignment
   expressions and compound assignment do not recover the sequence. This
   local also changes compiler symbol numbering and corrects the aim-4 square
   ordering. That secondary effect does not identify the original local name.
3. Native's smoke angle occupies frame-bottom `+0x10`, the existing `scalar`
   home. The separate `smoke_angle` occupied `+0x04`. Reusing `scalar` after
   its earlier value is dead fixes its store and both loads at `0x415a82`,
   `0x415ae2`, and `0x415b13`. The later ammo path assigns `scalar` again.
   `smoke-frame.json` records the baseline packer layout: scalar has weight
   18 and smoke angle weight 3. This is a source form compatible with the
   observed reuse, not proof of the original variable identity.

`regions.py` checks 11 straight-line regions: eight five-instruction movement
chains, both keyboard turn blocks, and smoke construction. Their 102
instructions total 483 encoded bytes. Only 32 COFF DIR32/REL32 fields are
masked, after checking both reference identity and the decoded operand-field
offset/width. Every other byte, including registers, stack offsets and
immediates, must match. Wrong-opcode and wrong-reference controls fail, as do
the corresponding regions when each selected source change is removed.

## Execution proof

`verify.py` executes the original image, baseline, retained source, and all
three leave-one-change-out controls over the existing 3,827 finite fixtures.
The retained source agrees with native on every observed final state byte
and ordered modeled callback argument. The baseline disagrees on 364 cases.
Removing the movement grouping restores all 364 mismatches. The turn and
smoke ablations have zero behavior mismatches in this matrix, while their
encoded-region checks fail. Native coverage is 4,198/4,206 instructions;
the retained candidate covers 4,203/4,211. The same eight native instructions
remain unvisited as in the shared point-frame proof.
`results.json` records individual observation hashes, mismatch case names,
source/object/body hashes, fixture/harness hashes and instruction coverage.

The shared runner uses gameplay x87 PC=24, round-to-nearest. Movement,
heading, vector and CRT conversion helpers execute their native machine code.
Input, RNG, normalization, allocations, effects, sound, reload and damage
boundaries are explicit models. This is a bounded routine proof, not
whole-game equivalence or exhaustive coverage of floating-point inputs.

## Unresolved regions and rejected hypotheses

- `0x413e5b..0x413e64`: the target index is loaded into ECX, while native
  uses EAX before the same scale-19 address computation. Integer types,
  field/reference forms, earlier declarations and clamping did not recover
  that choice without other losses.
- `0x414d02`: C2 clones four demo-angle instructions instead of jumping
  straight to the common tail. The preserving trace records tuple lengths
  `3, 0, 3, 0, 2, 0, 6, 5`: 19 estimated bytes, below the mover's 20-byte
  threshold. Eight IR tuples clone, including zero-size rounding nodes.
  Reversing the condition, local angle forms, conditional vectors, and float
  versus double atan did not recover native's shared tail. The estimate is
  before final stack/SIB encoding; it is not the final emitted byte count.
- `0x415741..0x41590e`: native keeps `normal_fire_ready` in BL; the candidate
  spills it to `[esp+0x11]`, then reloads BL. The baseline priority trace gives
  its long range priority -5. The weapon-swap block contributes -18; the
  eventual shorter range scores +2 and receives BL. Flag types, initialization
  placement, field references, condition forms, bool reuse, and swap/helper
  expansion did not recover the native long range.

`controls.json` preserves 68 compiled source variants as reversible edits to
the pinned baseline, with source hashes, all four scores, instruction counts
and reference audit counts. It includes the selected combination and its
three ablations; it is not a claim of 68 independent hypotheses. A separate
MSVC6 SP6 control has the same baseline scores and instruction count
(`msvc66.json`), giving no reason to change the canonical compiler.

The trace manifests record whole-object equality after clearing only the
COFF timestamp, rejecting missing streams, and no changed compiler decisions.
They describe diagnostic baseline builds, not matching candidates. Raw trace
streams and compiled artifacts stay in temporary output directories.

## Repository validation

The Crimson structural native link succeeds, and `crimson native verify`
finds both images' checked-in artifacts current. The matching checkpoint
reports zero regressions versus `cc035e42b`, with only `player_update`'s
matching result changed. Native-link and regression tests report 75 passes
and three failures loading the existing generated Grim platform archive:
`tools/native/providers/build/grim-platform/grim-platform.lib` hashes to
`5d7326c1a4d3da692a03ec984de89855f5716d78ec34b01bbc7fb6b886241a22`,
while the unchanged provider/provenance manifests require
`10c133faf469f31d2490c9b0569b98657e22b9a63e07a4e0b6b1beb949c17d22`.
That separate local artifact is not rewritten by this recovery.

## Reproduce

From the repository root, with the pinned local compiler and Unicorn 2.1.4:

```sh
uv run --with unicorn==2.1.4 python \
  tools/match/evidence/player-update-arithmetic-2026-09-27/verify.py \
  --out /tmp/player-update-arithmetic

uv run python tools/match/evidence/player-update-arithmetic-2026-09-27/controls.py \
  --out /tmp/player-update-controls --name combined --name without_movement_groups

uv run python tools/match/evidence/player-update-arithmetic-2026-09-27/clone_trace.py \
  /tmp/player-update-arithmetic/before --out /tmp/player-update-clone

uv run python scripts/c2/priority_trace.py /tmp/player-update-arithmetic/before \
  --out /tmp/player-update-priority --symbol 1738

uv run python scripts/c2/frame_predict.py /tmp/player-update-arithmetic/before \
  --out /tmp/player-update-frame --decisions --json /tmp/player-update-frame.json
```

Use fresh trace output directories. On macOS the Unicorn run needs local JIT
permission; a sandbox that disallows it can terminate Unicorn with SIGILL
before any fixture executes. The static region and compiler checks do not
depend on Unicorn execution.
