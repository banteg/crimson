# bonus_pick_random_type WIP

## Causal layout isolation (2026-09-22)

The [causality verifier](../../evidence/bonus-pick-layout-causality-2026-09-22/README.md)
reproduces all 77 reachable blocks in VC6's early reverse-postorder rebuild.
Dominance and acyclicity checks establish that changing successor visitation
order in this captured graph cannot place stage five after the retry latch.

At entry to C2+0x3663c, relocating the existing stage-five nodes after the
backedge and reusing stage four's existing skip jump as their exit yields
**encoded-exact native output**: 162 instructions and 20 clean references.
The disabled intervention preserves the whole ordinary COFF except timestamp;
the enabled intervention changes list links only and verifies node membership
and non-link fields. This is a compiler intervention, with no source recovery
or match credit. Canonical source, flags, and its non-exact status are unchanged.

The remaining source problem is now isolated: induce this placement while
preserving the shared Freeze destination and native hardcore branch polarity.
The known forward-scanning mover also considers an earlier skip spanning both
stages four and five, so making the tail unconditional alone is insufficient.
Further controls should demonstrate the intended intermediate-graph or pass
decision change, rather than rank alternative syntax by fuzzy score.

## Stage-five-only diagnostic and early ordering (2026-09-13)

The [preserving path follow-up](../../evidence/bonus-pick-layout-trace-2026-09-13/README.md#isolating-stage-5-and-locating-the-early-reorder)
now isolates a stage-5-only range move. Inverting the outer hardcore-stage-2
guard in the duplicated-Freeze-prefix control prevents stage 4 from moving with
it. The control remains non-exact: 169 instructions, seven extra filter
instructions, and the wrong hardcore rejection edge direction. It is retained
as a compiler-path diagnostic, outside the canonical scratches.

A separate preserving trace establishes that C2+0x12d16 pulls an explicitly
placed stage-5 tail back ahead of the retry condition, before global optimization
and allocation. The emitted body then equals canonical source byte-for-byte.
Manual source order therefore does not bypass the residual. The canonical
162-instruction source, compiler flags, and exactness remain unchanged.

## Preserving block-layout trace (2026-09-13)

[The late-pass replay](../../evidence/bonus-pick-layout-trace-2026-09-13/README.md)
locates the motion in the duplicated-filter controls at C2+0x3663c, through
the range-move helper called at C2+0x367ce. Canonical source does not invoke that
move. Its stage-4 skip destination has a conditional predecessor; the controls
supply an unconditional predecessor and move both stages 4 and 5. Duplicating
only the Freeze filter still retains five extra instructions and moves too much.
All three preserving traces reproduce their ordinary whole COFFs, apart from
timestamp, and retain 20 clean reference instructions.

This gives a concrete compiler gate for the next source hypothesis: recover a
stage-5-only movable range without retaining duplicate filters or sharing the
native stage-4 comparison. It does not establish the original source spelling;
canonical source, flags, and exactness remain unchanged.

## Instruction-graph proof (2026-09-11)

The independently replayable comparison in
`tools/match/evidence/bonus-pick-flow-graph-2026-09-11/` maps all 156
non-jump instructions one-to-one, preserves the taken and fall-through edges
of every conditional, covers all six unconditional jumps on each side, and
verifies all 20 reference instructions at their graph-mapped positions.
Deliberately changed conditions, destinations, and reference owners are rejected.
This strengthens the layout diagnosis without granting normalized or encoded
exactness; the original source spelling remains unrecovered.

An encoded-exact `dsound_restore_buffer` control demonstrates that the same
compiler can place a loop condition after a backward jump. Eight nested-retry
controls and 21 size-option controls on duplicated filters do not recover the
bonus selector. The latter merge code under size optimization but lose the
desired layout; the speed preference retains extra instructions. The package
records these bounded results and their reconstruction recipes.

Current best local score:

```txt
match=75.93% prefix=55/162 target_insns=162 candidate_insns=162 refs=20/0/0
```

The exact prefix recovers the fixed 16-entry bonus-pool scan, the retry counter,
the `rand() % 162 + 1` bucket draw, the rare Energizer acceptance roll, and the
complete ten-wide bonus bucket walk. Native tests `bucket <= 10` at the loop
head and `bucket_id < 15` on the backedge; expressing those as the two
structured loop conditions restores the native initialization order and grows
the exact prefix from 37 to 55 instructions.

The rejection paths now use ordinary `continue` statements and the retry limit
is the loop condition `retries++ < 100`. This reproduces native's success-first,
fallback-second return tail rather than the previous internal label and early
fallback return. The major-stage 4 Nuke and Freeze exclusions are also kept as
the two independent tests visible in native code. All 20 masked references
resolve to the intended globals, pool fields, constants, and helper calls.

The recovered filters also expose deliberate native player-slot asymmetry:
shield suppression reads player slots 0 and 1 directly, while My Favourite
Weapon and Death Clock use `perk_count_get`, which only reads player 0. The
Python and Zig ports previously generalized those checks across every active
player; the corresponding parity fix keeps the native slot rules explicit.

The remaining mismatch is confined to control-flow layout in the quest-specific
exclusions. Native places the final major-5 Nuke check after the retry backedge
and before both return tails, while VC6 keeps the same clean nested check beside the major-4
case. The displaced block changes downstream branch-target tokens even though
the instruction count, conditions, and references agree. Retain this natural
source unless stronger evidence explains that cold-block placement; do not
force it with a manual tail label, opaque boolean identities, or artificial
liveness.

## Recovery classification audit

Fresh Binary Ninja HLIL confirms the pool scan, bucket mapping, Energizer gate,
retry/fallback policy, every quest exclusion, shield asymmetry, perk checks,
weapon suppression, and metadata enable test. Candidate and native each have
162 instructions with `20/0/0` references. The localized delta is solely VC6's
cold-block placement and resulting branch-target layout; recovery is
`semantic-complete` with a `compiler` residual.

## Cold-block layout experiments

Live Binary Ninja disassembly confirms that the native stage-5 test is a
distinct tail block at `0x00412628`--`0x0041263e`. It reuses the already-loaded
major/minor values and compares `bonus_id` with the major value (both are 5)
before jumping back to the common post-quest filters. This supports the
recovered chained predicate and does not support introducing a second global
load or an artificial tail label.

The recorded `quest-stage-five-layout-mutations.json` sweep tested six natural
CFG spellings: nested and flat final predicates, an independent final test, an
explicit final `else`, reordered major-4/major-5 arms, and a combined major
guard. Five compiled byte-identically to the 75.93% baseline. The combined
guard gained only 3.43 fuzzy-weighted bytes while deleting three candidate
instructions and two mapped references by sharing the Nuke comparison across
major stages 4 and 5; native retains both comparisons, so that variant is
rejected. Stock 6.5 and 6.6 with `/GB` or `/G5` are identical, `/G6` regresses,
and the Processor Pack also regresses. The residual remains compiler block
placement, with the clean reference-complete source retained.

## Switch-layout controls

`quest-stage-switch-mutations.json` tests five natural switch reconstructions
of the major-4/major-5 quest exclusions. Putting either case in the switch
default is byte-for-byte neutral at 75.93%, 162/162 instructions, and audit
`20/0/0`. The two nested switch forms lose 2.99 weighted bytes, and the full
stage switch loses 14.94; none produces the native outlined major-5 block.

Together with the earlier six predicate-layout variants, these results show
that the tested switch forms do not recover the native layout. They do not
exclude other switch forms or establish why the original compiler placed the
block there. Recorded spec SHA:
`cdeec7b18eb188a4c8fe299d1759d1a876a50a798c42f65c34ccd3b3d1d94351`.

## Exact-neighbor house-style follow-up (2026-08-09)

The exact neighboring bonus functions suggest two recurring source shapes:
`bonus_try_spawn_on_kill` uses a local rejection flag before shared cleanup,
and `bonus_spawn_at_pos` uses a small ordinary inline helper for the accepted
body. Applying those shapes here does not recover the displaced stage-5 block.
A stage-5-only flag, a flag guarding the common acceptance path, a stage-5
inline predicate, a whole secondary-quest inline predicate, and a single
short-circuit secondary-quest predicate all remain at `75.9259259259%`,
`162/162` instructions, prefix `55`, and references `20/0/0`.

Factoring the entire common acceptance path into an inline helper regresses to
`74.8466%` with 164 candidate instructions and 19 mapped references. A shared
flag for every secondary quest rejection regresses to `74.691358%`. Inverting
the stage-4 predicate to spell the native `cmp 4` / non-stage-4 edge directly
regresses to `70.370370%` and `18/1/0` references because VC6 swaps the
major/minor register ownership. These results leave the clean nested source as
the strongest reference-complete reconstruction and further isolate the tail
placement as a compiler scheduling residual.

## Current-baseline cold-edge replay (2026-08-12)

The native-order load hypothesis was tested together with the inverted stage-4
edge, rather than replaying either shape alone. Five ordinary local declaration
orders snapshot `hardcore`, `quest_stage_minor`, and `quest_stage_major` before
the quest predicates. Three compile byte-identically to the current baseline;
the other two lose three weighted bytes and one mapped reference. In particular,
the native load order plus `major != 4` control flow is neutral, so source-level
temporary ownership does not explain the outlined stage-5 block.

The six predicate layouts and five switch layouts were then replayed against the
same current baseline. Every reference-complete candidate remains neutral or
regresses. The only fuzzy-score increase is the already-rejected combined major
guard (`+3.43` weighted bytes), which has 159 rather than 162 instructions and
only 18 rather than 20 mapped references because it merges two native Nuke
comparisons. None of these 16 compile-valid variants improves the retained
162-instruction, `20/0/0` reconstruction without a tradeoff. The displaced
cold edge remains unresolved.

## Batch 01 focused value boundaries (2026-09-05)

`batch-01-focused-value-boundaries-mutations.json` records 4 complete, compiling
controls against the 75.925926% baseline. The source forms are
`stage-five-positive-nested`, `stage-five-local-rejection`,
`stage-five-direct-else-guard`, `quest-eligibility-inline-boundary`.

No control improves the retained baseline without a metric tradeoff. Canonical source
and configuration are unchanged. These results bound the recorded hypothesis, not the
function's matchability.

## Bounded ownership follow-up (2026-09-07)

The 16 retry-budget and exit-ownership controls retain the original 101-attempt fallback policy while crossing loop form with the retry scalar lifetime. The shared retry label ties the original 75.925926%, 162/162 instructions, prefix 55, and 20 clean references; all other forms regress. The native cold quest-stage edge remains unresolved.

The checked-in mutation plans and recorded complete results bound these source forms; they do not establish that the function is unmatchable. Canonical source and configuration remain unchanged.

## Cold-edge source replay (2026-09-11)

[The replay package](../../evidence/bonus-pick-cold-edge-2026-09-11/README.md)
records 166 compiling source and compiler-option controls with reconstructible
edits and a verifier. They include acceptance and retry ownership, stage/bonus
predicates, assigned rejection flags, helper return forms, named constants,
declaration placement, and duplicated common filters. None is normalized or
encoded exact; the canonical source and configuration remain unchanged.

The 80.745342% Freeze-first shared-predicate candidate has only 160 instructions
and merges a comparison retained in native code. Duplicated filter paths can
move quest checks after the retry backedge but add instructions. Neither result
recovers the original sequence. The stage-5 tail placement remains open.

## Stage-five outline gate (2026-09-21)

Canonical source is unchanged: 162/162 instructions, prefix 55, references
`20/0/0`, 75.93%. The normalized difference is not a missing quest check. Both
sides have the same six stage-5 instructions. Native places them after the
retry backedge; the candidate keeps them between the stage-4 arm and the
shared Freeze filter, so stage-4 success needs an extra `jmp` that native
deletes by falling through.

C2+0x3663c can move that block. It fires only when an unconditional jump is
not a jump to the next instruction and the destination's previous node also
terminates unconditionally. A goto aimed at the Freeze check itself is deleted
before that pass. A goto aimed past the Freeze check survives and triggers the
move.

Fresh overlays against the current source, not retained:

- Inverting the hardcore stage-2 guard, with no extra goto, is rewritten back
  to the canonical body.
- Skipping the Freeze check without that inversion moves stage 4 and stage 5
  together: 160 instructions, 79.50%, prefix 55, `20/0/0`.
- Inversion plus a stage-5 goto past the shared Freeze check moves stage 5
  alone and leaves stage 4 hot. Instruction count returns to 162, the ratio
  rises to 81.48%, and references stay `20/0/0`. This is not a match. Opcode
  comparison against native leaves two real differences; the other normalized
  mismatches are label numbers shifted by those two:
  1. Hardcore Freeze rejection is `jne common; jmp retry` instead of native
     `je retry; jmp common`. Nested and split spellings of the same inverted
     guard keep that polarity.
  2. The outlined stage-5 minor and success exits land after the Freeze
     filter. Native lands on it. Aiming the goto at the filter makes the jump
     adjacent again, the pass does not fire, and the body returns to 75.93%.
- Duplicating the Freeze filter before the goto fixes the landing and still
  outlines stage 5 alone, but keeps the reversed edge and adds the seven
  filter instructions (169 instructions, 79.76%). That reproduces the earlier
  inverted-hardcore diagnostic.

The positive outer guard preserves the native edge and does not isolate stage
5. The inverted guard isolates stage 5 and does not preserve the edge. No
tested spelling separates those two effects, and no tested goto both survives
until C2+0x3663c and still targets the Freeze filter. Canonical source stays
the reference-complete body. The open problem is a stage-5-only movable range
whose exits target the shared Freeze filter and whose hardcore rejection keeps
`je retry; jmp common`.

Follow-up overlays did not separate those effects. Clause order
(`bonus == FREEZE && minor == 10`), a bonus-then-minor nest, and the same
outlining source under `msvc6.6` keep the reversed edge. A positive Freeze
rejection before the inverted chain emits native `je retry` but leaves the
reversed copy in place (168 instructions). Dropping that else still outlines
stage 5, then adds one `cmp major, 2` and swaps the hardcore byte into `cl`
and the minor into `edx`, so the aligned body gets worse. None is retained.

A preserving trace of the 162-instruction outlining overlay shows the
contradiction directly. C2+0x3663c selects the unconditional jump immediately
before the stage-5 chain. That chain is eight IL nodes and is inserted after
the retry backedge. Its last node is an unconditional jump to the shield
check, and that jump is the list-predecessor of the Freeze block, which is
why the gate accepts the move. A jump from that predecessor to the Freeze
block itself would be a jump to the next node and is deleted before this
pass; the canonical body is that deletion. For this tested source shape, the pass outlines stage 5
by making its exit skip the Freeze block. The final assembly still has
that skip. No later hooked mover retargets it. Canonical source stays.

The two remaining avenues were tested and do not open a match.

A node between a stage-5 goto and the Freeze label does not survive in the
right window. A dead local copy and an inline sink are removed early; both
compile back to the canonical 162-instruction body. A volatile copy survives
into the output (165 instructions, prefix 0, two reference mismatches).
`#pragma optimize("g", off)` deoptimizes the whole function to 191
instructions and does not outline stage 5.

The range mover has four other callers. A preserving trace records that none
of them run on the canonical body or on the 162-instruction outlining overlay.
Only C2+0x367ce runs, and only on that overlay. The C2+0x42830 tail of the
same pass is not taken. Canonical source stays.

The retained `filter-boundary-controls-2026-09-17.json` plan and corresponding
experiment-log entry cover 11 earlier filter-boundary controls. Seven compile
to the canonical score and instruction count; four retry-owner variants regress.
The plan and all 11 generated source hashes agree with the recorded results.

## Path-ownership interactions (2026-09-21)

`path-ownership-controls-2026-09-21.json` and the matching experiment record
retain 24 complete, compiling controls. No control improves the canonical
75.925926%, 162/162 instructions, prefix 55, and `20/0/0` references.

- Twelve controls put the common Freeze check on combinations of the hardcore
  stage-2, stage-4, and stage-5 paths before joining at the shield filter. They
  cross positive/inverted hardcore guards with six path subsets, excluding the
  already-studied stage-5-only subset. Every result retains extra instructions
  (167–177); the highest score is 75.739645% with 176 instructions and 20 clean
  references. Duplicating additional paths does not remove the extra filters.
- Twelve controls separate hardcore/normal paths or factor the major-stage test
  first, using if/switch secondary rules. Four separate the first Nuke rule too.
  The best result is 73.873874%, 171 instructions, prefix 55, and `20/0/0`.
  Its complete normalized diff shows a shared stage-4 rejection body but two
  stage-5 predicates before the common filters; native has one stage-5 predicate
  after the retry backedge. This tested factorization does not recover the tail.

Replay with `crimson match mutate tools/match/scratches/bonus_pick_random_type
--spec tools/match/scratches/bonus_pick_random_type/path-ownership-controls-2026-09-21.json
--max-variants 24`. Both source families are diagnostics; no probe is promoted.
The current canonical instruction graph still matches all 156 non-jump
instructions and 20 references with six transparent jumps per side. Normalized
and encoded-body exactness remain false. Canonical source and flags are unchanged.
