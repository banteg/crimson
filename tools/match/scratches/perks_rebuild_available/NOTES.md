# perks_rebuild_available WIP

Current best local score:

```txt
match=96.15% prefix=38/52 target_insns=52 candidate_insns=52 refs=18/0/0
```

The recovered source preserves the native full-table clear, base perk range,
four always-available perks, bounded quest-unlock scan, byte-sized availability
writes, and final Antiperk exclusion. All 18 masked references resolve to the
intended ids, metadata fields, and quest table boundaries.

The shared `perk_meta_t.available` field is now byte-sized with explicit
three-byte trailing padding. Every recovered access in this rebuild,
`perk_select_random`, and the unlock-database views is a byte read or write;
Binary Ninja now renders the same direct `uint8_t` field. Removing the former
integer-field casts preserves this WIP's 73.08% result and keeps
`perk_select_random` exact at 32/32 instructions.

The unconditional clear is behaviorally important. The Zig port previously
returned early when the quest unlock index was unchanged, allowing stale or
injected availability bits to survive. Native rebuilds on every call; the port
now does the same, with a regression test that dirties the table at the cached
index before rebuilding.

The quest scan first guards the zero-count case, then enters a bounded `do`
loop. This is the source shape exposed by the native CFG: the count is tested
before the quest cursor is materialized, the cursor and index occupy the
native `EDX` and `ECX` registers, and the count backedge follows each
availability write. Recovering that outer guard raises the candidate from
73.08% to 86.54% and aligns one additional reference without changing behavior
or instruction count.

Expressing the retained Antiperk location as its native word-stride index makes
the default VC6 and SP6 profiles load it through `EAX`, retain the scaled value
in `EDI`, and match the first 38 instructions. This raises the score from 86.54%
to 96.15%, reduces the fuzzy gap from 24.37 to 6.96 bytes, and aligns all 18
references without changing behavior or instruction count.

The remaining mismatch is confined to the quest-unlock loop. The candidate
proves the initial quest cursor is below the fixed table end and rotates that
bound check to the loop latch; native performs the upper-bound compare only on
the entry path before its count-bounded loop.
Tail-tested, pre-tested, conjunctive, pointer-bounded, struct-cursor, and
explicit-label forms were checked under both default VC6 and SP6. The
conjunctive form restores the native header and latch checks, but assigns the
cursor and index to the opposite registers and loses the 38-instruction prefix;
reusing earlier counter locals does not change that allocation. Forms that
retain the native 38-instruction prefix rotate the initial bound check instead.
The clean WIP remains preferable.

Recovery is classified `semantic-complete`; the bounded stock-VC6 source-shape
sweeps below close the remaining mismatch as a `compiler` residual.

## Recorded loop-shape boundary

`unlock-loop-shape-mutations.json` evaluates six complete pointer-headed,
count-latched, explicit-CFG, and conjunctive loop forms under the canonical
stock VC6 toolchain. All six compile to the same 52 instructions, 96.15%
score, 38-instruction prefix, and `18/0/0` references. This records the
optimizer fixed point instead of carrying equivalent cosmetic rewrites.

The processor-pack compiler can make this function exact, but image-wide Rich
header evidence rejects that compiler as the canonical executable toolchain.
That result remains a source-shape search signal, not a scratch override.

## Boundary-identity and combined-condition sweep

Live Binary Ninja identifies the native upper bound at `0x00484fe8`, exactly
the one-past end of `quest_selected_meta` and the start of
`creature_spawn_slot_table`. `unlock-end-identity-mutations.json` tested five
equivalent spellings through both owning objects and their first fields. Stock
VC6 canonicalized all five byte-for-byte to the 96.15% baseline, ruling out
linker-symbol identity as the reason the native pointer test remains at the
loop header.

`unlock-combined-condition-mutations.json` then tested count-first and
pointer-first `while`/`for` conditions plus a count-headed loop with an
internal pointer break. All five completed without truncation. The best three
fell to 84.62%, prefix 30, and 17 resolved references; the pointer-first forms
also lost two instructions. No source change was retained.

## One-time entry-bound sweep

`unlock-entry-boundary-mutations.json` records the direct source interpretation
of the native CFG: check the fixed table end once, then run a count-bounded
loop. Five nested, combined, and guard-order spellings were compiled with
stock VC6. The two closest forms shrink to 50 instructions, fall to 94.12%,
lose the 38-instruction prefix at instruction 30, and align only 17 references.
The three nested forms perturb the prologue and register allocation much more
severely. This confirms the native control-flow meaning but rules out the
ordinary C spellings under the supported compiler profile; the cleaner
52-instruction candidate remains retained.

## Residual classification

The loop-shape, boundary-identity, combined-condition, and one-time-entry-bound
sweeps exhaust the natural stock-VC6 spellings of the native control-flow
meaning. Processor Pack makes the function exact, but the executable's Rich
records reject that compiler profile. The retained source is therefore
semantic-complete with a `compiler` residual rather than an unbounded analysis
question.
