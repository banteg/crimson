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
bound check to the loop latch; native retains it at the loop header.
Tail-tested, pre-tested, conjunctive, pointer-bounded, struct-cursor, and
explicit-label forms were checked under both default VC6 and SP6. The
conjunctive form restores the native header and latch checks, but assigns the
cursor and index to the opposite registers and loses the 38-instruction prefix;
reusing earlier counter locals does not change that allocation. Forms that
retain the native 38-instruction prefix rotate the initial bound check instead.
The clean WIP remains preferable.

Recovery is classified `semantic-complete` with an `analysis` residual for the
unknown source shape.
