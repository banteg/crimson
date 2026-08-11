# bonus_pick_random_type WIP

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
exclusions. Native outlines the final major-5 Nuke check after the retry and
success blocks, while VC6 keeps the same clean nested check beside the major-4
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

## Switch-layout falsification

`quest-stage-switch-mutations.json` tests five natural switch reconstructions
of the major-4/major-5 quest exclusions. Putting either case in the switch
default is byte-for-byte neutral at 75.93%, 162/162 instructions, and audit
`20/0/0`. The two nested switch forms lose 2.99 weighted bytes, and the full
stage switch loses 14.94; none produces the native outlined major-5 block.

Together with the earlier six predicate-layout variants, this falsifies a
source `switch` as the missing shape. The residual is supported VC6 cold-block
placement, not unrecovered behavior. Recorded spec SHA:
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
comparisons. Across 16 current compile-valid variants, no tradeoff-free source
improvement exists; retain the 162-instruction, `20/0/0` reconstruction and
treat the displaced cold edge as a bounded compiler-layout residual.
