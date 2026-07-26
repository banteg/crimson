# perks_rebuild_available WIP

Current best local score:

```txt
match=88.46% prefix=9/52 target_insns=52 candidate_insns=52 refs=18/0/0
```

The recovered source preserves the native full-table clear, base perk range,
four always-available perks, bounded quest-unlock scan, byte-sized availability
writes, and final Antiperk exclusion. All 16 masked references resolve to the
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

The Processor Pack compiler is the stronger object-local provenance fit: it
raises the score from 86.54% to 88.46%, reduces the fuzzy gap from 24.37 to
20.88 bytes, and aligns all 18 references while preserving the 52-instruction
body and nine-instruction prefix. `/G4`, `/G5`, and `/GB` are identical under
that backend; `/G6` regresses.

The remaining mismatch is confined to two compiler choices. The candidate
assigns the initial Antiperk id load to `ECX` instead of native `EAX`, and
proves the initial quest cursor is below the fixed table end, rotating that
bound check to the loop latch. Function-scope and block-scope index/cursor
declarations compile identically; an outer-guarded conjunctive `while` loses
the recovered register assignment and reference. Writing unrelated global
loads inside the base-range loop would only steer scheduling and is not
plausible source, so the clean WIP remains preferable.
